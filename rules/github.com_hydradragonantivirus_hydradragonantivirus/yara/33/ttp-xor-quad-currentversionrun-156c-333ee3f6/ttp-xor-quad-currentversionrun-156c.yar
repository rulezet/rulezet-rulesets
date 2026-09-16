rule TTP_XOR_QUAD_CurrentVersionRun_156c {
  strings:
    $key_156c = { 46 03 [2] 62 0d [2] 49 21 [2] 67 03 [2] 73 18 [2] 7c 02 [2] 62 1f [2] 60 1e [2] 7b 18 [2] 67 1f [2] 7b 30 }

  condition:
    any of them
}