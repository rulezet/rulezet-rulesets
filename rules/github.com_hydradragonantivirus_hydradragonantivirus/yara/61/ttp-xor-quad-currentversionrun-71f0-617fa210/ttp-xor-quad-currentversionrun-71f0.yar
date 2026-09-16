rule TTP_XOR_QUAD_CurrentVersionRun_71f0 {
  strings:
    $key_71f0 = { 22 9f [2] 06 91 [2] 2d bd [2] 03 9f [2] 17 84 [2] 18 9e [2] 06 83 [2] 04 82 [2] 1f 84 [2] 03 83 [2] 1f ac }

  condition:
    any of them
}