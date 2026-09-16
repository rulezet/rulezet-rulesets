rule TTP_XOR_WriteProcessMemory_dacb {
  strings:
    $key_dacb = { 8d b9 [2] bf 9b [2] b9 ae [2] 97 ae [2] a8 b2 }

  condition:
    any of them
}