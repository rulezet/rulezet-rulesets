rule TTP_XOR_WriteProcessMemory_49cb {
  strings:
    $key_49cb = { 1e b9 [2] 2c 9b [2] 2a ae [2] 04 ae [2] 3b b2 }

  condition:
    any of them
}