rule TTP_XOR_WriteProcessMemory_bed4 {
  strings:
    $key_bed4 = { e9 a6 [2] db 84 [2] dd b1 [2] f3 b1 [2] cc ad }

  condition:
    any of them
}