rule TTP_XOR_QUAD_CurrentVersionRun_e501 {
  strings:
    $key_e501 = { b6 6e [2] 92 60 [2] b9 4c [2] 97 6e [2] 83 75 [2] 8c 6f [2] 92 72 [2] 90 73 [2] 8b 75 [2] 97 72 [2] 8b 5d }

  condition:
    any of them
}