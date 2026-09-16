rule TTP_XOR_WriteProcessMemory_0fdc {
  strings:
    $key_0fdc = { 58 ae [2] 6a 8c [2] 6c b9 [2] 42 b9 [2] 7d a5 }

  condition:
    any of them
}