rule TTP_XOR_WriteProcessMemory_bec3 {
  strings:
    $key_bec3 = { e9 b1 [2] db 93 [2] dd a6 [2] f3 a6 [2] cc ba }

  condition:
    any of them
}