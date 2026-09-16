rule TTP_XOR_WriteProcessMemory_05cb {
  strings:
    $key_05cb = { 52 b9 [2] 60 9b [2] 66 ae [2] 48 ae [2] 77 b2 }

  condition:
    any of them
}