rule TTP_XOR_QUAD_CurrentVersionRun_111a {
  strings:
    $key_111a = { 42 75 [2] 66 7b [2] 4d 57 [2] 63 75 [2] 77 6e [2] 78 74 [2] 66 69 [2] 64 68 [2] 7f 6e [2] 63 69 [2] 7f 46 }

  condition:
    any of them
}