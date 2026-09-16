rule TTP_XOR_WriteProcessMemory_0ccb {
  strings:
    $key_0ccb = { 5b b9 [2] 69 9b [2] 6f ae [2] 41 ae [2] 7e b2 }

  condition:
    any of them
}