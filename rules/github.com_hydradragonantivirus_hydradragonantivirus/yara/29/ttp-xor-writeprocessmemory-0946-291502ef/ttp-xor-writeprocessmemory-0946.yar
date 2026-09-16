rule TTP_XOR_WriteProcessMemory_0946 {
  strings:
    $key_0946 = { 5e 34 [2] 6c 16 [2] 6a 23 [2] 44 23 [2] 7b 3f }

  condition:
    any of them
}