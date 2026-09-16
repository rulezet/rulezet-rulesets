rule TTP_XOR_QUAD_CurrentVersionRun_262a {
  strings:
    $key_262a = { 75 45 [2] 51 4b [2] 7a 67 [2] 54 45 [2] 40 5e [2] 4f 44 [2] 51 59 [2] 53 58 [2] 48 5e [2] 54 59 [2] 48 76 }

  condition:
    any of them
}