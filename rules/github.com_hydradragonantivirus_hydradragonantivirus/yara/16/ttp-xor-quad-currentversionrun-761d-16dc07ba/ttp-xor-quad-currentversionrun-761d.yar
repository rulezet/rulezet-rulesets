rule TTP_XOR_QUAD_CurrentVersionRun_761d {
  strings:
    $key_761d = { 25 72 [2] 01 7c [2] 2a 50 [2] 04 72 [2] 10 69 [2] 1f 73 [2] 01 6e [2] 03 6f [2] 18 69 [2] 04 6e [2] 18 41 }

  condition:
    any of them
}