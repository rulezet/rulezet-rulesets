rule TTP_XOR_QUAD_CurrentVersionRun_66fd {
  strings:
    $key_66fd = { 35 92 [2] 11 9c [2] 3a b0 [2] 14 92 [2] 00 89 [2] 0f 93 [2] 11 8e [2] 13 8f [2] 08 89 [2] 14 8e [2] 08 a1 }

  condition:
    any of them
}