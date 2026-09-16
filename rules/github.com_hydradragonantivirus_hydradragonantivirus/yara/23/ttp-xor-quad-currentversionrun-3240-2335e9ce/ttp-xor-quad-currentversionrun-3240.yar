rule TTP_XOR_QUAD_CurrentVersionRun_3240 {
  strings:
    $key_3240 = { 61 2f [2] 45 21 [2] 6e 0d [2] 40 2f [2] 54 34 [2] 5b 2e [2] 45 33 [2] 47 32 [2] 5c 34 [2] 40 33 [2] 5c 1c }

  condition:
    any of them
}