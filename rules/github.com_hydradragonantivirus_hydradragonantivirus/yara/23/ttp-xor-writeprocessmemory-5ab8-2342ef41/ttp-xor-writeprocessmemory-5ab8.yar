rule TTP_XOR_WriteProcessMemory_5ab8 {
  strings:
    $key_5ab8 = { 0d ca [2] 3f e8 [2] 39 dd [2] 17 dd [2] 28 c1 }

  condition:
    any of them
}