rule TTP_XOR_WriteProcessMemory_eecb {
  strings:
    $key_eecb = { b9 b9 [2] 8b 9b [2] 8d ae [2] a3 ae [2] 9c b2 }

  condition:
    any of them
}