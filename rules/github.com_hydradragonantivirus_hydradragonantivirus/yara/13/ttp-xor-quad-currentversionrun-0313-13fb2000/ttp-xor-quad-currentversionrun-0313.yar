rule TTP_XOR_QUAD_CurrentVersionRun_0313 {
  strings:
    $key_0313 = { 50 7c [2] 74 72 [2] 5f 5e [2] 71 7c [2] 65 67 [2] 6a 7d [2] 74 60 [2] 76 61 [2] 6d 67 [2] 71 60 [2] 6d 4f }

  condition:
    any of them
}