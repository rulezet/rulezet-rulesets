rule TTP_XOR_WriteProcessMemory_dcb8 {
  strings:
    $key_dcb8 = { 8b ca [2] b9 e8 [2] bf dd [2] 91 dd [2] ae c1 }

  condition:
    any of them
}