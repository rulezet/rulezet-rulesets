rule TTP_XOR_WriteProcessMemory_5ecb {
  strings:
    $key_5ecb = { 09 b9 [2] 3b 9b [2] 3d ae [2] 13 ae [2] 2c b2 }

  condition:
    any of them
}