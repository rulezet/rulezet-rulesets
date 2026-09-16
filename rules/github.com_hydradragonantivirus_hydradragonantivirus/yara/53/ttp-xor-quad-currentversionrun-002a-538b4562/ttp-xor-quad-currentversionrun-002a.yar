rule TTP_XOR_QUAD_CurrentVersionRun_002a {
  strings:
    $key_002a = { 53 45 [2] 77 4b [2] 5c 67 [2] 72 45 [2] 66 5e [2] 69 44 [2] 77 59 [2] 75 58 [2] 6e 5e [2] 72 59 [2] 6e 76 }

  condition:
    any of them
}