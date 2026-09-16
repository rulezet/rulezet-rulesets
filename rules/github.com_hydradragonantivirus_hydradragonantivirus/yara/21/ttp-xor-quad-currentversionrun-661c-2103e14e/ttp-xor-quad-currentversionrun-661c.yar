rule TTP_XOR_QUAD_CurrentVersionRun_661c {
  strings:
    $key_661c = { 35 73 [2] 11 7d [2] 3a 51 [2] 14 73 [2] 00 68 [2] 0f 72 [2] 11 6f [2] 13 6e [2] 08 68 [2] 14 6f [2] 08 40 }

  condition:
    any of them
}