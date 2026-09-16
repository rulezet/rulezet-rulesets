rule TTP_XOR_QUAD_CurrentVersionRun_192a {
  strings:
    $key_192a = { 4a 45 [2] 6e 4b [2] 45 67 [2] 6b 45 [2] 7f 5e [2] 70 44 [2] 6e 59 [2] 6c 58 [2] 77 5e [2] 6b 59 [2] 77 76 }

  condition:
    any of them
}