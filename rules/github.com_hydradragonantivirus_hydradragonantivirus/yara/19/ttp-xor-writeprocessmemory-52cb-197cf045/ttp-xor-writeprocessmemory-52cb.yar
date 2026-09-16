rule TTP_XOR_WriteProcessMemory_52cb {
  strings:
    $key_52cb = { 05 b9 [2] 37 9b [2] 31 ae [2] 1f ae [2] 20 b2 }

  condition:
    any of them
}