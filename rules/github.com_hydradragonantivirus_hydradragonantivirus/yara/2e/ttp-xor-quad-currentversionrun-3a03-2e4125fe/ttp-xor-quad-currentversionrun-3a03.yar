rule TTP_XOR_QUAD_CurrentVersionRun_3a03 {
  strings:
    $key_3a03 = { 69 6c [2] 4d 62 [2] 66 4e [2] 48 6c [2] 5c 77 [2] 53 6d [2] 4d 70 [2] 4f 71 [2] 54 77 [2] 48 70 [2] 54 5f }

  condition:
    any of them
}