rule TTP_XOR_WriteProcessMemory_2ab8 {
  strings:
    $key_2ab8 = { 7d ca [2] 4f e8 [2] 49 dd [2] 67 dd [2] 58 c1 }

  condition:
    any of them
}