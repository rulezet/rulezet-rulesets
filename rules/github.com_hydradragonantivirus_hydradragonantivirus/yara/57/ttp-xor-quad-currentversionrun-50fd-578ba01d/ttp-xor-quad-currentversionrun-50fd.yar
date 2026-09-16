rule TTP_XOR_QUAD_CurrentVersionRun_50fd {
  strings:
    $key_50fd = { 03 92 [2] 27 9c [2] 0c b0 [2] 22 92 [2] 36 89 [2] 39 93 [2] 27 8e [2] 25 8f [2] 3e 89 [2] 22 8e [2] 3e a1 }

  condition:
    any of them
}