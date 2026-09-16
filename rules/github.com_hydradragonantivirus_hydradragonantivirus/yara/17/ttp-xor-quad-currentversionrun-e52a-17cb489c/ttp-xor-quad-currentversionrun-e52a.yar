rule TTP_XOR_QUAD_CurrentVersionRun_e52a {
  strings:
    $key_e52a = { b6 45 [2] 92 4b [2] b9 67 [2] 97 45 [2] 83 5e [2] 8c 44 [2] 92 59 [2] 90 58 [2] 8b 5e [2] 97 59 [2] 8b 76 }

  condition:
    any of them
}