rule TTP_XOR_QUAD_CurrentVersionRun_e51d {
  strings:
    $key_e51d = { b6 72 [2] 92 7c [2] b9 50 [2] 97 72 [2] 83 69 [2] 8c 73 [2] 92 6e [2] 90 6f [2] 8b 69 [2] 97 6e [2] 8b 41 }

  condition:
    any of them
}