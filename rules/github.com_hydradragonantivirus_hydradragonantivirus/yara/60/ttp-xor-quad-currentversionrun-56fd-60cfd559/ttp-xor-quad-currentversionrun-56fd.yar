rule TTP_XOR_QUAD_CurrentVersionRun_56fd {
  strings:
    $key_56fd = { 05 92 [2] 21 9c [2] 0a b0 [2] 24 92 [2] 30 89 [2] 3f 93 [2] 21 8e [2] 23 8f [2] 38 89 [2] 24 8e [2] 38 a1 }

  condition:
    any of them
}