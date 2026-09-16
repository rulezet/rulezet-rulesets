rule TTP_XOR_WriteProcessMemory_6ecb {
  strings:
    $key_6ecb = { 39 b9 [2] 0b 9b [2] 0d ae [2] 23 ae [2] 1c b2 }

  condition:
    any of them
}