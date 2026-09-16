rule TTP_XOR_WriteProcessMemory_3ec4 {
  strings:
    $key_3ec4 = { 69 b6 [2] 5b 94 [2] 5d a1 [2] 73 a1 [2] 4c bd }

  condition:
    any of them
}