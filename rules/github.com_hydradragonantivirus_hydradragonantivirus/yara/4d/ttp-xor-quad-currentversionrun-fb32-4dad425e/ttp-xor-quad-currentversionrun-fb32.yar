rule TTP_XOR_QUAD_CurrentVersionRun_fb32 {
  strings:
    $key_fb32 = { a8 5d [2] 8c 53 [2] a7 7f [2] 89 5d [2] 9d 46 [2] 92 5c [2] 8c 41 [2] 8e 40 [2] 95 46 [2] 89 41 [2] 95 6e }

  condition:
    any of them
}