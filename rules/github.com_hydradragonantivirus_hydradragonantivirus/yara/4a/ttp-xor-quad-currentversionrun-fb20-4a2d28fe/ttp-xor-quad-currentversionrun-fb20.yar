rule TTP_XOR_QUAD_CurrentVersionRun_fb20 {
  strings:
    $key_fb20 = { a8 4f [2] 8c 41 [2] a7 6d [2] 89 4f [2] 9d 54 [2] 92 4e [2] 8c 53 [2] 8e 52 [2] 95 54 [2] 89 53 [2] 95 7c }

  condition:
    any of them
}