rule TTP_XOR_QUAD_CurrentVersionRun_fb56 {
  strings:
    $key_fb56 = { a8 39 [2] 8c 37 [2] a7 1b [2] 89 39 [2] 9d 22 [2] 92 38 [2] 8c 25 [2] 8e 24 [2] 95 22 [2] 89 25 [2] 95 0a }

  condition:
    any of them
}