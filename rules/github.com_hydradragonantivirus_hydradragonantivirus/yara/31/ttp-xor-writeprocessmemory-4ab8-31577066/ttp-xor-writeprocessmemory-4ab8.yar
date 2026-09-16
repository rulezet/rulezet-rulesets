rule TTP_XOR_WriteProcessMemory_4ab8 {
  strings:
    $key_4ab8 = { 1d ca [2] 2f e8 [2] 29 dd [2] 07 dd [2] 38 c1 }

  condition:
    any of them
}