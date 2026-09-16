rule TTP_XOR_WriteProcessMemory_05b8 {
  strings:
    $key_05b8 = { 52 ca [2] 60 e8 [2] 66 dd [2] 48 dd [2] 77 c1 }

  condition:
    any of them
}