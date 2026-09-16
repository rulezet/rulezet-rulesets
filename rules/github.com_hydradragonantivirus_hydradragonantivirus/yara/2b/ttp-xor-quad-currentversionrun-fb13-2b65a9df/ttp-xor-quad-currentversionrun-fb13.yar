rule TTP_XOR_QUAD_CurrentVersionRun_fb13 {
  strings:
    $key_fb13 = { a8 7c [2] 8c 72 [2] a7 5e [2] 89 7c [2] 9d 67 [2] 92 7d [2] 8c 60 [2] 8e 61 [2] 95 67 [2] 89 60 [2] 95 4f }

  condition:
    any of them
}