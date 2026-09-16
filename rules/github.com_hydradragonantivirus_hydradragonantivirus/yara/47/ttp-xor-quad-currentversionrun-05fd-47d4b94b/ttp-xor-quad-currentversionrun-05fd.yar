rule TTP_XOR_QUAD_CurrentVersionRun_05fd {
  strings:
    $key_05fd = { 56 92 [2] 72 9c [2] 59 b0 [2] 77 92 [2] 63 89 [2] 6c 93 [2] 72 8e [2] 70 8f [2] 6b 89 [2] 77 8e [2] 6b a1 }

  condition:
    any of them
}