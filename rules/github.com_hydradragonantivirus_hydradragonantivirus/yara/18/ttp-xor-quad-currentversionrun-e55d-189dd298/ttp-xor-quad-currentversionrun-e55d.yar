rule TTP_XOR_QUAD_CurrentVersionRun_e55d {
  strings:
    $key_e55d = { b6 32 [2] 92 3c [2] b9 10 [2] 97 32 [2] 83 29 [2] 8c 33 [2] 92 2e [2] 90 2f [2] 8b 29 [2] 97 2e [2] 8b 01 }

  condition:
    any of them
}