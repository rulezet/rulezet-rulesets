rule TTP_XOR_QUAD_CurrentVersionRun_6366 {
  strings:
    $key_6366 = { 30 09 [2] 14 07 [2] 3f 2b [2] 11 09 [2] 05 12 [2] 0a 08 [2] 14 15 [2] 16 14 [2] 0d 12 [2] 11 15 [2] 0d 3a }

  condition:
    any of them
}