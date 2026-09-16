rule TTP_XOR_QUAD_CurrentVersionRun_2d71 {
  strings:
    $key_2d71 = { 7e 1e [2] 5a 10 [2] 71 3c [2] 5f 1e [2] 4b 05 [2] 44 1f [2] 5a 02 [2] 58 03 [2] 43 05 [2] 5f 02 [2] 43 2d }

  condition:
    any of them
}