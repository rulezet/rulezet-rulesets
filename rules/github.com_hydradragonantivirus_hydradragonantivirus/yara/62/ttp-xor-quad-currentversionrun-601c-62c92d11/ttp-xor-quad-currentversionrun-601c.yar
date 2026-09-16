rule TTP_XOR_QUAD_CurrentVersionRun_601c {
  strings:
    $key_601c = { 33 73 [2] 17 7d [2] 3c 51 [2] 12 73 [2] 06 68 [2] 09 72 [2] 17 6f [2] 15 6e [2] 0e 68 [2] 12 6f [2] 0e 40 }

  condition:
    any of them
}