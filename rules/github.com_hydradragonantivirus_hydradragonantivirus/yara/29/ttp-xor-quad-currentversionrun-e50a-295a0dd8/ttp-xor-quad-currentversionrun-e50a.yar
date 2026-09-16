rule TTP_XOR_QUAD_CurrentVersionRun_e50a {
  strings:
    $key_e50a = { b6 65 [2] 92 6b [2] b9 47 [2] 97 65 [2] 83 7e [2] 8c 64 [2] 92 79 [2] 90 78 [2] 8b 7e [2] 97 79 [2] 8b 56 }

  condition:
    any of them
}