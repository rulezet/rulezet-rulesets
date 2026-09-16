rule TTP_XOR_QUAD_CurrentVersionRun_38fa {
  strings:
    $key_38fa = { 6b 95 [2] 4f 9b [2] 64 b7 [2] 4a 95 [2] 5e 8e [2] 51 94 [2] 4f 89 [2] 4d 88 [2] 56 8e [2] 4a 89 [2] 56 a6 }

  condition:
    any of them
}