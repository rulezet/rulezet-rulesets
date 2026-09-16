rule TTP_XOR_QUAD_CurrentVersionRun_6510 {
  strings:
    $key_6510 = { 36 7f [2] 12 71 [2] 39 5d [2] 17 7f [2] 03 64 [2] 0c 7e [2] 12 63 [2] 10 62 [2] 0b 64 [2] 17 63 [2] 0b 4c }

  condition:
    any of them
}