rule TTP_XOR_QUAD_CurrentVersionRun_f0fd {
  strings:
    $key_f0fd = { a3 92 [2] 87 9c [2] ac b0 [2] 82 92 [2] 96 89 [2] 99 93 [2] 87 8e [2] 85 8f [2] 9e 89 [2] 82 8e [2] 9e a1 }

  condition:
    any of them
}