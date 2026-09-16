rule TTP_XOR_WriteProcessMemory_cab8 {
  strings:
    $key_cab8 = { 9d ca [2] af e8 [2] a9 dd [2] 87 dd [2] b8 c1 }

  condition:
    any of them
}