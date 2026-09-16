rule TTP_XOR_QUAD_CurrentVersionRun_3c2a {
  strings:
    $key_3c2a = { 6f 45 [2] 4b 4b [2] 60 67 [2] 4e 45 [2] 5a 5e [2] 55 44 [2] 4b 59 [2] 49 58 [2] 52 5e [2] 4e 59 [2] 52 76 }

  condition:
    any of them
}