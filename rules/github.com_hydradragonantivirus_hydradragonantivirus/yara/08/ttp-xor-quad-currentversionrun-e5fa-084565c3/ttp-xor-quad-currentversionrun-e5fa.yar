rule TTP_XOR_QUAD_CurrentVersionRun_e5fa {
  strings:
    $key_e5fa = { b6 95 [2] 92 9b [2] b9 b7 [2] 97 95 [2] 83 8e [2] 8c 94 [2] 92 89 [2] 90 88 [2] 8b 8e [2] 97 89 [2] 8b a6 }

  condition:
    any of them
}