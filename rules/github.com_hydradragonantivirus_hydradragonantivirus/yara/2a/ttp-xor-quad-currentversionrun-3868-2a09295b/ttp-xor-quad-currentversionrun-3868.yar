rule TTP_XOR_QUAD_CurrentVersionRun_3868 {
  strings:
    $key_3868 = { 6b 07 [2] 4f 09 [2] 64 25 [2] 4a 07 [2] 5e 1c [2] 51 06 [2] 4f 1b [2] 4d 1a [2] 56 1c [2] 4a 1b [2] 56 34 }

  condition:
    any of them
}