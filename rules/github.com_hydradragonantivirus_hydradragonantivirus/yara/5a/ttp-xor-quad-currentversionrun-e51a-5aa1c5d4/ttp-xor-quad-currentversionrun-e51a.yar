rule TTP_XOR_QUAD_CurrentVersionRun_e51a {
  strings:
    $key_e51a = { b6 75 [2] 92 7b [2] b9 57 [2] 97 75 [2] 83 6e [2] 8c 74 [2] 92 69 [2] 90 68 [2] 8b 6e [2] 97 69 [2] 8b 46 }

  condition:
    any of them
}