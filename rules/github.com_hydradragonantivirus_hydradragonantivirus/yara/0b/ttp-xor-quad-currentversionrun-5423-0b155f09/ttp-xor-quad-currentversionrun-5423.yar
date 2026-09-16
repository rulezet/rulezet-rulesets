rule TTP_XOR_QUAD_CurrentVersionRun_5423 {
  strings:
    $key_5423 = { 07 4c [2] 23 42 [2] 08 6e [2] 26 4c [2] 32 57 [2] 3d 4d [2] 23 50 [2] 21 51 [2] 3a 57 [2] 26 50 [2] 3a 7f }

  condition:
    any of them
}