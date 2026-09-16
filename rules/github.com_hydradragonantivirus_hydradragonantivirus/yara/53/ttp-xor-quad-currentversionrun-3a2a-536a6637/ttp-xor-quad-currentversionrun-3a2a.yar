rule TTP_XOR_QUAD_CurrentVersionRun_3a2a {
  strings:
    $key_3a2a = { 69 45 [2] 4d 4b [2] 66 67 [2] 48 45 [2] 5c 5e [2] 53 44 [2] 4d 59 [2] 4f 58 [2] 54 5e [2] 48 59 [2] 54 76 }

  condition:
    any of them
}