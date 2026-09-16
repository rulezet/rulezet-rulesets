rule TTP_XOR_QUAD_CurrentVersionRun_3b7b {
  strings:
    $key_3b7b = { 68 14 [2] 4c 1a [2] 67 36 [2] 49 14 [2] 5d 0f [2] 52 15 [2] 4c 08 [2] 4e 09 [2] 55 0f [2] 49 08 [2] 55 27 }

  condition:
    any of them
}