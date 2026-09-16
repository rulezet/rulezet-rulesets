rule TTP_XOR_QUAD_CurrentVersionRun_37fd {
  strings:
    $key_37fd = { 64 92 [2] 40 9c [2] 6b b0 [2] 45 92 [2] 51 89 [2] 5e 93 [2] 40 8e [2] 42 8f [2] 59 89 [2] 45 8e [2] 59 a1 }

  condition:
    any of them
}