rule TTP_XOR_WriteProcessMemory_c8b8 {
  strings:
    $key_c8b8 = { 9f ca [2] ad e8 [2] ab dd [2] 85 dd [2] ba c1 }

  condition:
    any of them
}