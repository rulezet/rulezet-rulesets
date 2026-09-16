rule TTP_XOR_QUAD_CurrentVersionRun_7138 {
  strings:
    $key_7138 = { 22 57 [2] 06 59 [2] 2d 75 [2] 03 57 [2] 17 4c [2] 18 56 [2] 06 4b [2] 04 4a [2] 1f 4c [2] 03 4b [2] 1f 64 }

  condition:
    any of them
}