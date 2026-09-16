rule TTP_XOR_QUAD_CurrentVersionRun_23fd {
  strings:
    $key_23fd = { 70 92 [2] 54 9c [2] 7f b0 [2] 51 92 [2] 45 89 [2] 4a 93 [2] 54 8e [2] 56 8f [2] 4d 89 [2] 51 8e [2] 4d a1 }

  condition:
    any of them
}