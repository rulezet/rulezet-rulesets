rule TTP_XOR_WriteProcessMemory_06cb {
  strings:
    $key_06cb = { 51 b9 [2] 63 9b [2] 65 ae [2] 4b ae [2] 74 b2 }

  condition:
    any of them
}