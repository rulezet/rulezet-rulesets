rule TTP_XOR_QUAD_CurrentVersionRun_221c {
  strings:
    $key_221c = { 71 73 [2] 55 7d [2] 7e 51 [2] 50 73 [2] 44 68 [2] 4b 72 [2] 55 6f [2] 57 6e [2] 4c 68 [2] 50 6f [2] 4c 40 }

  condition:
    any of them
}