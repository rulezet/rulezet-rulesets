rule TTP_XOR_WriteProcessMemory_11b8 {
  strings:
    $key_11b8 = { 46 ca [2] 74 e8 [2] 72 dd [2] 5c dd [2] 63 c1 }

  condition:
    any of them
}