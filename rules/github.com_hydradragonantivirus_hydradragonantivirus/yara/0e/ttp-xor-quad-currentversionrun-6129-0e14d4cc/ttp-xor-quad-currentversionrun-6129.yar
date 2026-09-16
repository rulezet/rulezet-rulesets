rule TTP_XOR_QUAD_CurrentVersionRun_6129 {
  strings:
    $key_6129 = { 32 46 [2] 16 48 [2] 3d 64 [2] 13 46 [2] 07 5d [2] 08 47 [2] 16 5a [2] 14 5b [2] 0f 5d [2] 13 5a [2] 0f 75 }

  condition:
    any of them
}