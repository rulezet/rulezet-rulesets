rule TTP_XOR_QUAD_CurrentVersionRun_49fd {
  strings:
    $key_49fd = { 1a 92 [2] 3e 9c [2] 15 b0 [2] 3b 92 [2] 2f 89 [2] 20 93 [2] 3e 8e [2] 3c 8f [2] 27 89 [2] 3b 8e [2] 27 a1 }

  condition:
    any of them
}