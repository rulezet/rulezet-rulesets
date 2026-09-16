rule TTP_XOR_WriteProcessMemory_0966 {
  strings:
    $key_0966 = { 5e 14 [2] 6c 36 [2] 6a 03 [2] 44 03 [2] 7b 1f }

  condition:
    any of them
}