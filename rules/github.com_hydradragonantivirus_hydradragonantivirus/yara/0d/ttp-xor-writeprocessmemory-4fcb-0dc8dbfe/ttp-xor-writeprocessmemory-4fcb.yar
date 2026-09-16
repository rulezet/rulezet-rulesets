rule TTP_XOR_WriteProcessMemory_4fcb {
  strings:
    $key_4fcb = { 18 b9 [2] 2a 9b [2] 2c ae [2] 02 ae [2] 3d b2 }

  condition:
    any of them
}