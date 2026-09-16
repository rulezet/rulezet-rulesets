rule TTP_XOR_WriteProcessMemory_02cb {
  strings:
    $key_02cb = { 55 b9 [2] 67 9b [2] 61 ae [2] 4f ae [2] 70 b2 }

  condition:
    any of them
}