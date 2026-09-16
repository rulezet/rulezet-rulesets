rule TTP_XOR_QUAD_CurrentVersionRun_fb02 {
  strings:
    $key_fb02 = { a8 6d [2] 8c 63 [2] a7 4f [2] 89 6d [2] 9d 76 [2] 92 6c [2] 8c 71 [2] 8e 70 [2] 95 76 [2] 89 71 [2] 95 5e }

  condition:
    any of them
}