rule TTP_XOR_QUAD_CurrentVersionRun_39fa {
  strings:
    $key_39fa = { 6a 95 [2] 4e 9b [2] 65 b7 [2] 4b 95 [2] 5f 8e [2] 50 94 [2] 4e 89 [2] 4c 88 [2] 57 8e [2] 4b 89 [2] 57 a6 }

  condition:
    any of them
}