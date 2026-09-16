rule TTP_XOR_QUAD_CurrentVersionRun_e366 {
  strings:
    $key_e366 = { b0 09 [2] 94 07 [2] bf 2b [2] 91 09 [2] 85 12 [2] 8a 08 [2] 94 15 [2] 96 14 [2] 8d 12 [2] 91 15 [2] 8d 3a }

  condition:
    any of them
}