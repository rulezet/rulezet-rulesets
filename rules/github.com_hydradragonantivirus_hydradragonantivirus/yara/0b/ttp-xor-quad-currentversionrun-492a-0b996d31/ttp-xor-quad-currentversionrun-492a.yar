rule TTP_XOR_QUAD_CurrentVersionRun_492a {
  strings:
    $key_492a = { 1a 45 [2] 3e 4b [2] 15 67 [2] 3b 45 [2] 2f 5e [2] 20 44 [2] 3e 59 [2] 3c 58 [2] 27 5e [2] 3b 59 [2] 27 76 }

  condition:
    any of them
}