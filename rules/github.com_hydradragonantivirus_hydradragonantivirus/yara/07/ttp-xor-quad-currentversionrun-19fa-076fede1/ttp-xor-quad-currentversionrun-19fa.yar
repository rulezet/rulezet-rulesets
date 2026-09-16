rule TTP_XOR_QUAD_CurrentVersionRun_19fa {
  strings:
    $key_19fa = { 4a 95 [2] 6e 9b [2] 45 b7 [2] 6b 95 [2] 7f 8e [2] 70 94 [2] 6e 89 [2] 6c 88 [2] 77 8e [2] 6b 89 [2] 77 a6 }

  condition:
    any of them
}