rule TTP_XOR_QUAD_CurrentVersionRun_3303 {
  strings:
    $key_3303 = { 60 6c [2] 44 62 [2] 6f 4e [2] 41 6c [2] 55 77 [2] 5a 6d [2] 44 70 [2] 46 71 [2] 5d 77 [2] 41 70 [2] 5d 5f }

  condition:
    any of them
}