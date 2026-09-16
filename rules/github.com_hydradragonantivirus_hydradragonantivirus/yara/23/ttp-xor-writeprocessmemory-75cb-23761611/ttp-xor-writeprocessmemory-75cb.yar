rule TTP_XOR_WriteProcessMemory_75cb {
  strings:
    $key_75cb = { 22 b9 [2] 10 9b [2] 16 ae [2] 38 ae [2] 07 b2 }

  condition:
    any of them
}