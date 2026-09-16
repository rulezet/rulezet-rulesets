rule TTP_XOR_QUAD_CurrentVersionRun_fb3b {
  strings:
    $key_fb3b = { a8 54 [2] 8c 5a [2] a7 76 [2] 89 54 [2] 9d 4f [2] 92 55 [2] 8c 48 [2] 8e 49 [2] 95 4f [2] 89 48 [2] 95 67 }

  condition:
    any of them
}