rule TTP_XOR_QUAD_CurrentVersionRun_10fd {
  strings:
    $key_10fd = { 43 92 [2] 67 9c [2] 4c b0 [2] 62 92 [2] 76 89 [2] 79 93 [2] 67 8e [2] 65 8f [2] 7e 89 [2] 62 8e [2] 7e a1 }

  condition:
    any of them
}