rule TTP_XOR_WriteProcessMemory_4fdc {
  strings:
    $key_4fdc = { 18 ae [2] 2a 8c [2] 2c b9 [2] 02 b9 [2] 3d a5 }

  condition:
    any of them
}