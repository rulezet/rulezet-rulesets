rule TTP_XOR_WriteProcessMemory_dcbb {
  strings:
    $key_dcbb = { 8b c9 [2] b9 eb [2] bf de [2] 91 de [2] ae c2 }

  condition:
    any of them
}