rule TTP_XOR_QUAD_CurrentVersionRun_fb3f {
  strings:
    $key_fb3f = { a8 50 [2] 8c 5e [2] a7 72 [2] 89 50 [2] 9d 4b [2] 92 51 [2] 8c 4c [2] 8e 4d [2] 95 4b [2] 89 4c [2] 95 63 }

  condition:
    any of them
}