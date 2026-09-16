rule TTP_XOR_QUAD_CurrentVersionRun_242a {
  strings:
    $key_242a = { 77 45 [2] 53 4b [2] 78 67 [2] 56 45 [2] 42 5e [2] 4d 44 [2] 53 59 [2] 51 58 [2] 4a 5e [2] 56 59 [2] 4a 76 }

  condition:
    any of them
}