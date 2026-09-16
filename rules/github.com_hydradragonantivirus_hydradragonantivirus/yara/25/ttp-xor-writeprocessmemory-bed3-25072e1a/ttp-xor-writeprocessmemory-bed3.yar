rule TTP_XOR_WriteProcessMemory_bed3 {
  strings:
    $key_bed3 = { e9 a1 [2] db 83 [2] dd b6 [2] f3 b6 [2] cc aa }

  condition:
    any of them
}