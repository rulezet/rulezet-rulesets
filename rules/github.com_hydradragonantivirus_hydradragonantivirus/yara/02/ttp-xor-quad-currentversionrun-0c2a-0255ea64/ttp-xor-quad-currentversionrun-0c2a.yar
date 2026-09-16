rule TTP_XOR_QUAD_CurrentVersionRun_0c2a {
  strings:
    $key_0c2a = { 5f 45 [2] 7b 4b [2] 50 67 [2] 7e 45 [2] 6a 5e [2] 65 44 [2] 7b 59 [2] 79 58 [2] 62 5e [2] 7e 59 [2] 62 76 }

  condition:
    any of them
}