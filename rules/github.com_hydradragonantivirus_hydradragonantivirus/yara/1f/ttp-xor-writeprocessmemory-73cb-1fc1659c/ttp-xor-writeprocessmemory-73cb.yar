rule TTP_XOR_WriteProcessMemory_73cb {
  strings:
    $key_73cb = { 24 b9 [2] 16 9b [2] 10 ae [2] 3e ae [2] 01 b2 }

  condition:
    any of them
}