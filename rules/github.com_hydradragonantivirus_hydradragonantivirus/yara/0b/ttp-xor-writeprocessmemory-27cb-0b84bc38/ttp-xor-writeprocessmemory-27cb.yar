rule TTP_XOR_WriteProcessMemory_27cb {
  strings:
    $key_27cb = { 70 b9 [2] 42 9b [2] 44 ae [2] 6a ae [2] 55 b2 }

  condition:
    any of them
}