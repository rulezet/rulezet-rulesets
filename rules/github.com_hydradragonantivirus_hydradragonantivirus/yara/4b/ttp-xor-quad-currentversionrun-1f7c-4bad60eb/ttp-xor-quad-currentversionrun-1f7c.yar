rule TTP_XOR_QUAD_CurrentVersionRun_1f7c {
  strings:
    $key_1f7c = { 4c 13 [2] 68 1d [2] 43 31 [2] 6d 13 [2] 79 08 [2] 76 12 [2] 68 0f [2] 6a 0e [2] 71 08 [2] 6d 0f [2] 71 20 }

  condition:
    any of them
}