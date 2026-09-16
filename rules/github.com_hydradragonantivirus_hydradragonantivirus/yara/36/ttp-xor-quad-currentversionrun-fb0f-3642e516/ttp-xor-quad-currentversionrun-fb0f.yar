rule TTP_XOR_QUAD_CurrentVersionRun_fb0f {
  strings:
    $key_fb0f = { a8 60 [2] 8c 6e [2] a7 42 [2] 89 60 [2] 9d 7b [2] 92 61 [2] 8c 7c [2] 8e 7d [2] 95 7b [2] 89 7c [2] 95 53 }

  condition:
    any of them
}