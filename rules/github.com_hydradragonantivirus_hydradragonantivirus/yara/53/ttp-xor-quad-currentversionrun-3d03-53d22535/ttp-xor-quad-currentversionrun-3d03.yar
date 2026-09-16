rule TTP_XOR_QUAD_CurrentVersionRun_3d03 {
  strings:
    $key_3d03 = { 6e 6c [2] 4a 62 [2] 61 4e [2] 4f 6c [2] 5b 77 [2] 54 6d [2] 4a 70 [2] 48 71 [2] 53 77 [2] 4f 70 [2] 53 5f }

  condition:
    any of them
}