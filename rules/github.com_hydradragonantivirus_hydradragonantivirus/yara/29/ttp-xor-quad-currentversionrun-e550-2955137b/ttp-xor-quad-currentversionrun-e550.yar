rule TTP_XOR_QUAD_CurrentVersionRun_e550 {
  strings:
    $key_e550 = { b6 3f [2] 92 31 [2] b9 1d [2] 97 3f [2] 83 24 [2] 8c 3e [2] 92 23 [2] 90 22 [2] 8b 24 [2] 97 23 [2] 8b 0c }

  condition:
    any of them
}