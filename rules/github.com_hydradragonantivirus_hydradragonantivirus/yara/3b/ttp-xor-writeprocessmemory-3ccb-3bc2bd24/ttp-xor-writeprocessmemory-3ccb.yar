rule TTP_XOR_WriteProcessMemory_3ccb {
  strings:
    $key_3ccb = { 6b b9 [2] 59 9b [2] 5f ae [2] 71 ae [2] 4e b2 }

  condition:
    any of them
}