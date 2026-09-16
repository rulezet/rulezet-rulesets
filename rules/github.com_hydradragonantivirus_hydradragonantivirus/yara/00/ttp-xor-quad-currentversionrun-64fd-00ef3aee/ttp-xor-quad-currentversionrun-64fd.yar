rule TTP_XOR_QUAD_CurrentVersionRun_64fd {
  strings:
    $key_64fd = { 37 92 [2] 13 9c [2] 38 b0 [2] 16 92 [2] 02 89 [2] 0d 93 [2] 13 8e [2] 11 8f [2] 0a 89 [2] 16 8e [2] 0a a1 }

  condition:
    any of them
}