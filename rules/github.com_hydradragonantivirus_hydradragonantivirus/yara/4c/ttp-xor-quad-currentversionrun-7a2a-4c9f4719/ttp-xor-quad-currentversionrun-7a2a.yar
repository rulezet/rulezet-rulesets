rule TTP_XOR_QUAD_CurrentVersionRun_7a2a {
  strings:
    $key_7a2a = { 29 45 [2] 0d 4b [2] 26 67 [2] 08 45 [2] 1c 5e [2] 13 44 [2] 0d 59 [2] 0f 58 [2] 14 5e [2] 08 59 [2] 14 76 }

  condition:
    any of them
}