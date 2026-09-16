rule TTP_XOR_QUAD_CurrentVersionRun_041c {
  strings:
    $key_041c = { 57 73 [2] 73 7d [2] 58 51 [2] 76 73 [2] 62 68 [2] 6d 72 [2] 73 6f [2] 71 6e [2] 6a 68 [2] 76 6f [2] 6a 40 }

  condition:
    any of them
}