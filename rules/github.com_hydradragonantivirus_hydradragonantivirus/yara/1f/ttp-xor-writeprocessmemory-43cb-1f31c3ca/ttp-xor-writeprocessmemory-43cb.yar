rule TTP_XOR_WriteProcessMemory_43cb {
  strings:
    $key_43cb = { 14 b9 [2] 26 9b [2] 20 ae [2] 0e ae [2] 31 b2 }

  condition:
    any of them
}