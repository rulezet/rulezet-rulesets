rule TTP_XOR_WriteProcessMemory_39cb {
  strings:
    $key_39cb = { 6e b9 [2] 5c 9b [2] 5a ae [2] 74 ae [2] 4b b2 }

  condition:
    any of them
}