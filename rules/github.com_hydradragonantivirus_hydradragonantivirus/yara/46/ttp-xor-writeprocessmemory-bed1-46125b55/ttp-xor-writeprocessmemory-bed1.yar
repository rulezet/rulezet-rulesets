rule TTP_XOR_WriteProcessMemory_bed1 {
  strings:
    $key_bed1 = { e9 a3 [2] db 81 [2] dd b4 [2] f3 b4 [2] cc a8 }

  condition:
    any of them
}