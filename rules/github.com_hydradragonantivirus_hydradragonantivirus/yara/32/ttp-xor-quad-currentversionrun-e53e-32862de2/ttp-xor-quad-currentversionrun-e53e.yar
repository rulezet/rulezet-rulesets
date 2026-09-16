rule TTP_XOR_QUAD_CurrentVersionRun_e53e {
  strings:
    $key_e53e = { b6 51 [2] 92 5f [2] b9 73 [2] 97 51 [2] 83 4a [2] 8c 50 [2] 92 4d [2] 90 4c [2] 8b 4a [2] 97 4d [2] 8b 62 }

  condition:
    any of them
}