rule TTP_XOR_WriteProcessMemory_47cb {
  strings:
    $key_47cb = { 10 b9 [2] 22 9b [2] 24 ae [2] 0a ae [2] 35 b2 }

  condition:
    any of them
}