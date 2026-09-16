rule TTP_XOR_QUAD_CurrentVersionRun_fb1f {
  strings:
    $key_fb1f = { a8 70 [2] 8c 7e [2] a7 52 [2] 89 70 [2] 9d 6b [2] 92 71 [2] 8c 6c [2] 8e 6d [2] 95 6b [2] 89 6c [2] 95 43 }

  condition:
    any of them
}