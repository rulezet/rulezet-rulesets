rule TTP_XOR_WriteProcessMemory_4ec4 {
  strings:
    $key_4ec4 = { 19 b6 [2] 2b 94 [2] 2d a1 [2] 03 a1 [2] 3c bd }

  condition:
    any of them
}