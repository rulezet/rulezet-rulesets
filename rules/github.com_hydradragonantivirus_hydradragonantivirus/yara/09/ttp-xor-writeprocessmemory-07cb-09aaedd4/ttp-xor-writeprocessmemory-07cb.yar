rule TTP_XOR_WriteProcessMemory_07cb {
  strings:
    $key_07cb = { 50 b9 [2] 62 9b [2] 64 ae [2] 4a ae [2] 75 b2 }

  condition:
    any of them
}