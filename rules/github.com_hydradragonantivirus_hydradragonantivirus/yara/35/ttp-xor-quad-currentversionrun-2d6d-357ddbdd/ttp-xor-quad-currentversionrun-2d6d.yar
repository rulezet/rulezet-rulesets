rule TTP_XOR_QUAD_CurrentVersionRun_2d6d {
  strings:
    $key_2d6d = { 7e 02 [2] 5a 0c [2] 71 20 [2] 5f 02 [2] 4b 19 [2] 44 03 [2] 5a 1e [2] 58 1f [2] 43 19 [2] 5f 1e [2] 43 31 }

  condition:
    any of them
}