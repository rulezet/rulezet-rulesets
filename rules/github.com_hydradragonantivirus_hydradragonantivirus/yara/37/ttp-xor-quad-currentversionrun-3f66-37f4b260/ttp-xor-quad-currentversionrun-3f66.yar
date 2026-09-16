rule TTP_XOR_QUAD_CurrentVersionRun_3f66 {
  strings:
    $key_3f66 = { 6c 09 [2] 48 07 [2] 63 2b [2] 4d 09 [2] 59 12 [2] 56 08 [2] 48 15 [2] 4a 14 [2] 51 12 [2] 4d 15 [2] 51 3a }

  condition:
    any of them
}