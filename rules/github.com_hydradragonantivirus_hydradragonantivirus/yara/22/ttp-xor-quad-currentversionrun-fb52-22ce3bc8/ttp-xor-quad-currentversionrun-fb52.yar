rule TTP_XOR_QUAD_CurrentVersionRun_fb52 {
  strings:
    $key_fb52 = { a8 3d [2] 8c 33 [2] a7 1f [2] 89 3d [2] 9d 26 [2] 92 3c [2] 8c 21 [2] 8e 20 [2] 95 26 [2] 89 21 [2] 95 0e }

  condition:
    any of them
}