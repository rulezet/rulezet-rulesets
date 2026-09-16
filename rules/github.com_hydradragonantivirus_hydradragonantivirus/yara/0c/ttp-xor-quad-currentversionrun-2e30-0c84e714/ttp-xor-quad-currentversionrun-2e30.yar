rule TTP_XOR_QUAD_CurrentVersionRun_2e30 {
  strings:
    $key_2e30 = { 7d 5f [2] 59 51 [2] 72 7d [2] 5c 5f [2] 48 44 [2] 47 5e [2] 59 43 [2] 5b 42 [2] 40 44 [2] 5c 43 [2] 40 6c }

  condition:
    any of them
}