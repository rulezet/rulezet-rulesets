rule TTP_XOR_WriteProcessMemory_19cb {
  strings:
    $key_19cb = { 4e b9 [2] 7c 9b [2] 7a ae [2] 54 ae [2] 6b b2 }

  condition:
    any of them
}