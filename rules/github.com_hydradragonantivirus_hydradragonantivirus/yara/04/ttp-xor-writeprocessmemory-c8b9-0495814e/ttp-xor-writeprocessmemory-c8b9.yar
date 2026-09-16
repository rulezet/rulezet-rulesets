rule TTP_XOR_WriteProcessMemory_c8b9 {
  strings:
    $key_c8b9 = { 9f cb [2] ad e9 [2] ab dc [2] 85 dc [2] ba c0 }

  condition:
    any of them
}