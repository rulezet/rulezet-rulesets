rule TTP_XOR_QUAD_CurrentVersionRun_0f13 {
  strings:
    $key_0f13 = { 5c 7c [2] 78 72 [2] 53 5e [2] 7d 7c [2] 69 67 [2] 66 7d [2] 78 60 [2] 7a 61 [2] 61 67 [2] 7d 60 [2] 61 4f }

  condition:
    any of them
}