rule TTP_XOR_QUAD_CurrentVersionRun_55fd {
  strings:
    $key_55fd = { 06 92 [2] 22 9c [2] 09 b0 [2] 27 92 [2] 33 89 [2] 3c 93 [2] 22 8e [2] 20 8f [2] 3b 89 [2] 27 8e [2] 3b a1 }

  condition:
    any of them
}