rule TTP_XOR_WriteProcessMemory_6ccb {
  strings:
    $key_6ccb = { 3b b9 [2] 09 9b [2] 0f ae [2] 21 ae [2] 1e b2 }

  condition:
    any of them
}