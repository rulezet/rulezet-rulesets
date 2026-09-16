rule TTP_XOR_QUAD_CurrentVersionRun_eb03 {
  strings:
    $key_eb03 = { b8 6c [2] 9c 62 [2] b7 4e [2] 99 6c [2] 8d 77 [2] 82 6d [2] 9c 70 [2] 9e 71 [2] 85 77 [2] 99 70 [2] 85 5f }

  condition:
    any of them
}