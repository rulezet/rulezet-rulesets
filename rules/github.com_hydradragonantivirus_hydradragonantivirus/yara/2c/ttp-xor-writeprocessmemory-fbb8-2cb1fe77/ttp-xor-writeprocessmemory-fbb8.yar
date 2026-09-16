rule TTP_XOR_WriteProcessMemory_fbb8 {
  strings:
    $key_fbb8 = { ac ca [2] 9e e8 [2] 98 dd [2] b6 dd [2] 89 c1 }

  condition:
    any of them
}