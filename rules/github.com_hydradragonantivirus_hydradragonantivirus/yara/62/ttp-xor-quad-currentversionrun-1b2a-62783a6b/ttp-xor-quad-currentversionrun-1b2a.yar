rule TTP_XOR_QUAD_CurrentVersionRun_1b2a {
  strings:
    $key_1b2a = { 48 45 [2] 6c 4b [2] 47 67 [2] 69 45 [2] 7d 5e [2] 72 44 [2] 6c 59 [2] 6e 58 [2] 75 5e [2] 69 59 [2] 75 76 }

  condition:
    any of them
}