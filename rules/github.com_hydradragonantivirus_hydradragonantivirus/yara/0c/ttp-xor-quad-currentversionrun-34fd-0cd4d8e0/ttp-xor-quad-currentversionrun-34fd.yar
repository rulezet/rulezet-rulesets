rule TTP_XOR_QUAD_CurrentVersionRun_34fd {
  strings:
    $key_34fd = { 67 92 [2] 43 9c [2] 68 b0 [2] 46 92 [2] 52 89 [2] 5d 93 [2] 43 8e [2] 41 8f [2] 5a 89 [2] 46 8e [2] 5a a1 }

  condition:
    any of them
}