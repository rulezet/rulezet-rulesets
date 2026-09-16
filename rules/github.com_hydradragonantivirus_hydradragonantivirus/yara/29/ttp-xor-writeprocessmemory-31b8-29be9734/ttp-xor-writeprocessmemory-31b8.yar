rule TTP_XOR_WriteProcessMemory_31b8 {
  strings:
    $key_31b8 = { 66 ca [2] 54 e8 [2] 52 dd [2] 7c dd [2] 43 c1 }

  condition:
    any of them
}