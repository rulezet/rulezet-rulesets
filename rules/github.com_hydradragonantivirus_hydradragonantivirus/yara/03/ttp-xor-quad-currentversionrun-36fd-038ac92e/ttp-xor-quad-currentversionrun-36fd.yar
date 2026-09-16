rule TTP_XOR_QUAD_CurrentVersionRun_36fd {
  strings:
    $key_36fd = { 65 92 [2] 41 9c [2] 6a b0 [2] 44 92 [2] 50 89 [2] 5f 93 [2] 41 8e [2] 43 8f [2] 58 89 [2] 44 8e [2] 58 a1 }

  condition:
    any of them
}