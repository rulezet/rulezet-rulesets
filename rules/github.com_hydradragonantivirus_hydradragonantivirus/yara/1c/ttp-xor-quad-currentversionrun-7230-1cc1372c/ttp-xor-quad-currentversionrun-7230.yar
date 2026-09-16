rule TTP_XOR_QUAD_CurrentVersionRun_7230 {
  strings:
    $key_7230 = { 21 5f [2] 05 51 [2] 2e 7d [2] 00 5f [2] 14 44 [2] 1b 5e [2] 05 43 [2] 07 42 [2] 1c 44 [2] 00 43 [2] 1c 6c }

  condition:
    any of them
}