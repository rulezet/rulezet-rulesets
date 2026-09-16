rule TTP_XOR_QUAD_CurrentVersionRun_fb3e {
  strings:
    $key_fb3e = { a8 51 [2] 8c 5f [2] a7 73 [2] 89 51 [2] 9d 4a [2] 92 50 [2] 8c 4d [2] 8e 4c [2] 95 4a [2] 89 4d [2] 95 62 }

  condition:
    any of them
}