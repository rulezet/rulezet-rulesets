rule TTP_XOR_WriteProcessMemory_8acb {
  strings:
    $key_8acb = { dd b9 [2] ef 9b [2] e9 ae [2] c7 ae [2] f8 b2 }

  condition:
    any of them
}