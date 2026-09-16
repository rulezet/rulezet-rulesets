rule TTP_XOR_QUAD_CurrentVersionRun_3875 {
  strings:
    $key_3875 = { 6b 1a [2] 4f 14 [2] 64 38 [2] 4a 1a [2] 5e 01 [2] 51 1b [2] 4f 06 [2] 4d 07 [2] 56 01 [2] 4a 06 [2] 56 29 }

  condition:
    any of them
}