rule TTP_XOR_QUAD_CurrentVersionRun_327b {
  strings:
    $key_327b = { 61 14 [2] 45 1a [2] 6e 36 [2] 40 14 [2] 54 0f [2] 5b 15 [2] 45 08 [2] 47 09 [2] 5c 0f [2] 40 08 [2] 5c 27 }

  condition:
    any of them
}