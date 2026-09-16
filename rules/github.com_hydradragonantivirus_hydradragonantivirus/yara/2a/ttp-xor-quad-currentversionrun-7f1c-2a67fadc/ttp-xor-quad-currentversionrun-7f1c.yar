rule TTP_XOR_QUAD_CurrentVersionRun_7f1c {
  strings:
    $key_7f1c = { 2c 73 [2] 08 7d [2] 23 51 [2] 0d 73 [2] 19 68 [2] 16 72 [2] 08 6f [2] 0a 6e [2] 11 68 [2] 0d 6f [2] 11 40 }

  condition:
    any of them
}