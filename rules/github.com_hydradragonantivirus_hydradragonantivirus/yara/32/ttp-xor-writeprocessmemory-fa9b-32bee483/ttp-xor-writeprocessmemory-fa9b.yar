rule TTP_XOR_WriteProcessMemory_fa9b {
  strings:
    $key_fa9b = { ad e9 [2] 9f cb [2] 99 fe [2] b7 fe [2] 88 e2 }

  condition:
    any of them
}