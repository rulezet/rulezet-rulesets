rule TTP_XOR_QUAD_CurrentVersionRun_78fd {
  strings:
    $key_78fd = { 2b 92 [2] 0f 9c [2] 24 b0 [2] 0a 92 [2] 1e 89 [2] 11 93 [2] 0f 8e [2] 0d 8f [2] 16 89 [2] 0a 8e [2] 16 a1 }

  condition:
    any of them
}