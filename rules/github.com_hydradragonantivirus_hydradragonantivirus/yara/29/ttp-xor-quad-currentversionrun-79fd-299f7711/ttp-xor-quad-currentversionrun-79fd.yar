rule TTP_XOR_QUAD_CurrentVersionRun_79fd {
  strings:
    $key_79fd = { 2a 92 [2] 0e 9c [2] 25 b0 [2] 0b 92 [2] 1f 89 [2] 10 93 [2] 0e 8e [2] 0c 8f [2] 17 89 [2] 0b 8e [2] 17 a1 }

  condition:
    any of them
}