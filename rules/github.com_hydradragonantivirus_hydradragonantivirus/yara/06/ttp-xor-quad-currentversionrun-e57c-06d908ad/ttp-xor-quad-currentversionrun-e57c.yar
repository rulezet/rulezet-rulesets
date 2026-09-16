rule TTP_XOR_QUAD_CurrentVersionRun_e57c {
  strings:
    $key_e57c = { b6 13 [2] 92 1d [2] b9 31 [2] 97 13 [2] 83 08 [2] 8c 12 [2] 92 0f [2] 90 0e [2] 8b 08 [2] 97 0f [2] 8b 20 }

  condition:
    any of them
}