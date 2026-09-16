rule TTP_XOR_WriteProcessMemory_69cb {
  strings:
    $key_69cb = { 3e b9 [2] 0c 9b [2] 0a ae [2] 24 ae [2] 1b b2 }

  condition:
    any of them
}