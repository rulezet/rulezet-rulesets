rule TTP_XOR_WriteProcessMemory_3ecb {
  strings:
    $key_3ecb = { 69 b9 [2] 5b 9b [2] 5d ae [2] 73 ae [2] 4c b2 }

  condition:
    any of them
}