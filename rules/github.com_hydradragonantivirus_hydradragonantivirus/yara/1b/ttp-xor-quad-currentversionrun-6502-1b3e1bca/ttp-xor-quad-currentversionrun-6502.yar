rule TTP_XOR_QUAD_CurrentVersionRun_6502 {
  strings:
    $key_6502 = { 36 6d [2] 12 63 [2] 39 4f [2] 17 6d [2] 03 76 [2] 0c 6c [2] 12 71 [2] 10 70 [2] 0b 76 [2] 17 71 [2] 0b 5e }

  condition:
    any of them
}