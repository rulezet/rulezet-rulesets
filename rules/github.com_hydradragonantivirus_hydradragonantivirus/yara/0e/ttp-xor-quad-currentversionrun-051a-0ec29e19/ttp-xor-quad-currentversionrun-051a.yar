rule TTP_XOR_QUAD_CurrentVersionRun_051a {
  strings:
    $key_051a = { 56 75 [2] 72 7b [2] 59 57 [2] 77 75 [2] 63 6e [2] 6c 74 [2] 72 69 [2] 70 68 [2] 6b 6e [2] 77 69 [2] 6b 46 }

  condition:
    any of them
}