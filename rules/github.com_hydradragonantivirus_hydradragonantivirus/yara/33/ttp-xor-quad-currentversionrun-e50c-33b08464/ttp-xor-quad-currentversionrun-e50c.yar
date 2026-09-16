rule TTP_XOR_QUAD_CurrentVersionRun_e50c {
  strings:
    $key_e50c = { b6 63 [2] 92 6d [2] b9 41 [2] 97 63 [2] 83 78 [2] 8c 62 [2] 92 7f [2] 90 7e [2] 8b 78 [2] 97 7f [2] 8b 50 }

  condition:
    any of them
}