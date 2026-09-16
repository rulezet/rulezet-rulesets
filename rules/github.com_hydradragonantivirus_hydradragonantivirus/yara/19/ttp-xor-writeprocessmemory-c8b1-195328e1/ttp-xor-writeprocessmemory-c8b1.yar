rule TTP_XOR_WriteProcessMemory_c8b1 {
  strings:
    $key_c8b1 = { 9f c3 [2] ad e1 [2] ab d4 [2] 85 d4 [2] ba c8 }

  condition:
    any of them
}