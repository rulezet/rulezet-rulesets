rule TTP_XOR_QUAD_CurrentVersionRun_207b {
  strings:
    $key_207b = { 73 14 [2] 57 1a [2] 7c 36 [2] 52 14 [2] 46 0f [2] 49 15 [2] 57 08 [2] 55 09 [2] 4e 0f [2] 52 08 [2] 4e 27 }

  condition:
    any of them
}