rule TTP_XOR_WriteProcessMemory_bec2 {
  strings:
    $key_bec2 = { e9 b0 [2] db 92 [2] dd a7 [2] f3 a7 [2] cc bb }

  condition:
    any of them
}