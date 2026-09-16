rule TTP_XOR_WriteProcessMemory_52b8 {
  strings:
    $key_52b8 = { 05 ca [2] 37 e8 [2] 31 dd [2] 1f dd [2] 20 c1 }

  condition:
    any of them
}