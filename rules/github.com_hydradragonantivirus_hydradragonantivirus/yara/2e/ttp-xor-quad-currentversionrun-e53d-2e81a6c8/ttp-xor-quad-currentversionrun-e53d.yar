rule TTP_XOR_QUAD_CurrentVersionRun_e53d {
  strings:
    $key_e53d = { b6 52 [2] 92 5c [2] b9 70 [2] 97 52 [2] 83 49 [2] 8c 53 [2] 92 4e [2] 90 4f [2] 8b 49 [2] 97 4e [2] 8b 61 }

  condition:
    any of them
}