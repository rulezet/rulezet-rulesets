rule TTP_XOR_QUAD_CurrentVersionRun_651c {
  strings:
    $key_651c = { 36 73 [2] 12 7d [2] 39 51 [2] 17 73 [2] 03 68 [2] 0c 72 [2] 12 6f [2] 10 6e [2] 0b 68 [2] 17 6f [2] 0b 40 }

  condition:
    any of them
}