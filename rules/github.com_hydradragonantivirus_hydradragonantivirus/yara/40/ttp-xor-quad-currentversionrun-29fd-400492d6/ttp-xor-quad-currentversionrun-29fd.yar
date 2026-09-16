rule TTP_XOR_QUAD_CurrentVersionRun_29fd {
  strings:
    $key_29fd = { 7a 92 [2] 5e 9c [2] 75 b0 [2] 5b 92 [2] 4f 89 [2] 40 93 [2] 5e 8e [2] 5c 8f [2] 47 89 [2] 5b 8e [2] 47 a1 }

  condition:
    any of them
}