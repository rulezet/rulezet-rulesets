rule TTP_XOR_QUAD_CurrentVersionRun_62fa {
  strings:
    $key_62fa = { 31 95 [2] 15 9b [2] 3e b7 [2] 10 95 [2] 04 8e [2] 0b 94 [2] 15 89 [2] 17 88 [2] 0c 8e [2] 10 89 [2] 0c a6 }

  condition:
    any of them
}