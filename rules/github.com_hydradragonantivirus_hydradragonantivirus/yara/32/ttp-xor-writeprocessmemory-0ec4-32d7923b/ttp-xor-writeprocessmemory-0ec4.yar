rule TTP_XOR_WriteProcessMemory_0ec4 {
  strings:
    $key_0ec4 = { 59 b6 [2] 6b 94 [2] 6d a1 [2] 43 a1 [2] 7c bd }

  condition:
    any of them
}