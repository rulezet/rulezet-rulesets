rule TTP_XOR_WriteProcessMemory_2bb8 {
  strings:
    $key_2bb8 = { 7c ca [2] 4e e8 [2] 48 dd [2] 66 dd [2] 59 c1 }

  condition:
    any of them
}