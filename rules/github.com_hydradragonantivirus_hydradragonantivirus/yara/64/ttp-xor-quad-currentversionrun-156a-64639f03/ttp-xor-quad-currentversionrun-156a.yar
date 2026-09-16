rule TTP_XOR_QUAD_CurrentVersionRun_156a {
  strings:
    $key_156a = { 46 05 [2] 62 0b [2] 49 27 [2] 67 05 [2] 73 1e [2] 7c 04 [2] 62 19 [2] 60 18 [2] 7b 1e [2] 67 19 [2] 7b 36 }

  condition:
    any of them
}