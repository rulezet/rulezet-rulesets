rule TTP_XOR_WriteProcessMemory_72cb {
  strings:
    $key_72cb = { 25 b9 [2] 17 9b [2] 11 ae [2] 3f ae [2] 00 b2 }

  condition:
    any of them
}