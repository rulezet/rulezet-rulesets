rule TTP_XOR_QUAD_CurrentVersionRun_12fd {
  strings:
    $key_12fd = { 41 92 [2] 65 9c [2] 4e b0 [2] 60 92 [2] 74 89 [2] 7b 93 [2] 65 8e [2] 67 8f [2] 7c 89 [2] 60 8e [2] 7c a1 }

  condition:
    any of them
}