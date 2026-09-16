rule TTP_XOR_QUAD_CurrentVersionRun_3b1b {
  strings:
    $key_3b1b = { 68 74 [2] 4c 7a [2] 67 56 [2] 49 74 [2] 5d 6f [2] 52 75 [2] 4c 68 [2] 4e 69 [2] 55 6f [2] 49 68 [2] 55 47 }

  condition:
    any of them
}