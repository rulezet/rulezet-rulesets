rule TTP_XOR_QUAD_CurrentVersionRun_1803 {
  strings:
    $key_1803 = { 4b 6c [2] 6f 62 [2] 44 4e [2] 6a 6c [2] 7e 77 [2] 71 6d [2] 6f 70 [2] 6d 71 [2] 76 77 [2] 6a 70 [2] 76 5f }

  condition:
    any of them
}