rule TTP_XOR_QUAD_CurrentVersionRun_62fd {
  strings:
    $key_62fd = { 31 92 [2] 15 9c [2] 3e b0 [2] 10 92 [2] 04 89 [2] 0b 93 [2] 15 8e [2] 17 8f [2] 0c 89 [2] 10 8e [2] 0c a1 }

  condition:
    any of them
}