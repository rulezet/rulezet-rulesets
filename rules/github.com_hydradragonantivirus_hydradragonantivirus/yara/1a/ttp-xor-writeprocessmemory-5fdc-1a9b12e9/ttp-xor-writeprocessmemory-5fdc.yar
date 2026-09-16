rule TTP_XOR_WriteProcessMemory_5fdc {
  strings:
    $key_5fdc = { 08 ae [2] 3a 8c [2] 3c b9 [2] 12 b9 [2] 2d a5 }

  condition:
    any of them
}