rule TTP_XOR_WriteProcessMemory_96f4 {
  strings:
    $key_96f4 = { c1 86 [2] f3 a4 [2] f5 91 [2] db 91 [2] e4 8d }

  condition:
    any of them
}