rule TTP_XOR_QUAD_CurrentVersionRun_fb2e {
  strings:
    $key_fb2e = { a8 41 [2] 8c 4f [2] a7 63 [2] 89 41 [2] 9d 5a [2] 92 40 [2] 8c 5d [2] 8e 5c [2] 95 5a [2] 89 5d [2] 95 72 }

  condition:
    any of them
}