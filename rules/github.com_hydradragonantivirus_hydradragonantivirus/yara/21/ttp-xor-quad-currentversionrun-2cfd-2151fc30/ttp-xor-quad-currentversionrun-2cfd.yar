rule TTP_XOR_QUAD_CurrentVersionRun_2cfd {
  strings:
    $key_2cfd = { 7f 92 [2] 5b 9c [2] 70 b0 [2] 5e 92 [2] 4a 89 [2] 45 93 [2] 5b 8e [2] 59 8f [2] 42 89 [2] 5e 8e [2] 42 a1 }

  condition:
    any of them
}