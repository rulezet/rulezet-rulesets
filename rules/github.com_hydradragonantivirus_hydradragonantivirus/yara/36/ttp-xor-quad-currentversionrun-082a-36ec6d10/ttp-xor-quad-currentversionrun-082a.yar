rule TTP_XOR_QUAD_CurrentVersionRun_082a {
  strings:
    $key_082a = { 5b 45 [2] 7f 4b [2] 54 67 [2] 7a 45 [2] 6e 5e [2] 61 44 [2] 7f 59 [2] 7d 58 [2] 66 5e [2] 7a 59 [2] 66 76 }

  condition:
    any of them
}