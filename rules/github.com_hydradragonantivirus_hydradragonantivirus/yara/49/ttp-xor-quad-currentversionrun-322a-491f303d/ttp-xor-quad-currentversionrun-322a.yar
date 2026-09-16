rule TTP_XOR_QUAD_CurrentVersionRun_322a {
  strings:
    $key_322a = { 61 45 [2] 45 4b [2] 6e 67 [2] 40 45 [2] 54 5e [2] 5b 44 [2] 45 59 [2] 47 58 [2] 5c 5e [2] 40 59 [2] 5c 76 }

  condition:
    any of them
}