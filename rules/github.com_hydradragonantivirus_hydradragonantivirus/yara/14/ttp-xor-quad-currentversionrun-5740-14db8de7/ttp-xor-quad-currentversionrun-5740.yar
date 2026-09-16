rule TTP_XOR_QUAD_CurrentVersionRun_5740 {
  strings:
    $key_5740 = { 04 2f [2] 20 21 [2] 0b 0d [2] 25 2f [2] 31 34 [2] 3e 2e [2] 20 33 [2] 22 32 [2] 39 34 [2] 25 33 [2] 39 1c }

  condition:
    any of them
}