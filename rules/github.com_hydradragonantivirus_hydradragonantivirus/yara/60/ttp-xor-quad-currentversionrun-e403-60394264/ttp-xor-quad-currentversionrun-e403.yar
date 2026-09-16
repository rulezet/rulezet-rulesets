rule TTP_XOR_QUAD_CurrentVersionRun_e403 {
  strings:
    $key_e403 = { b7 6c [2] 93 62 [2] b8 4e [2] 96 6c [2] 82 77 [2] 8d 6d [2] 93 70 [2] 91 71 [2] 8a 77 [2] 96 70 [2] 8a 5f }

  condition:
    any of them
}