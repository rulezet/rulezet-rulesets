rule TTP_XOR_QUAD_CurrentVersionRun_5113 {
  strings:
    $key_5113 = { 02 7c [2] 26 72 [2] 0d 5e [2] 23 7c [2] 37 67 [2] 38 7d [2] 26 60 [2] 24 61 [2] 3f 67 [2] 23 60 [2] 3f 4f }

  condition:
    any of them
}