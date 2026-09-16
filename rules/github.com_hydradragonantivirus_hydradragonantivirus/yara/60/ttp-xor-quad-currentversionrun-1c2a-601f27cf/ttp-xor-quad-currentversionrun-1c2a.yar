rule TTP_XOR_QUAD_CurrentVersionRun_1c2a {
  strings:
    $key_1c2a = { 4f 45 [2] 6b 4b [2] 40 67 [2] 6e 45 [2] 7a 5e [2] 75 44 [2] 6b 59 [2] 69 58 [2] 72 5e [2] 6e 59 [2] 72 76 }

  condition:
    any of them
}