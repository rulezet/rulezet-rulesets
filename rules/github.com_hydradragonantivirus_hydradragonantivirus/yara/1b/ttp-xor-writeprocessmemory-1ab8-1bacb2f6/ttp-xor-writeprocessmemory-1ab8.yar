rule TTP_XOR_WriteProcessMemory_1ab8 {
  strings:
    $key_1ab8 = { 4d ca [2] 7f e8 [2] 79 dd [2] 57 dd [2] 68 c1 }

  condition:
    any of them
}