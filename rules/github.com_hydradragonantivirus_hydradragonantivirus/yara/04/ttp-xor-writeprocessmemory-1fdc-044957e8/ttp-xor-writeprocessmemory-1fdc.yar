rule TTP_XOR_WriteProcessMemory_1fdc {
  strings:
    $key_1fdc = { 48 ae [2] 7a 8c [2] 7c b9 [2] 52 b9 [2] 6d a5 }

  condition:
    any of them
}