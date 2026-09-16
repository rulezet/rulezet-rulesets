rule TTP_XOR_WriteProcessMemory_bec5 {
  strings:
    $key_bec5 = { e9 b7 [2] db 95 [2] dd a0 [2] f3 a0 [2] cc bc }

  condition:
    any of them
}