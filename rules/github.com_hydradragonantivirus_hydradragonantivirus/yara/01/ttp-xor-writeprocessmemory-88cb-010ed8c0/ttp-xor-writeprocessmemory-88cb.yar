rule TTP_XOR_WriteProcessMemory_88cb {
  strings:
    $key_88cb = { df b9 [2] ed 9b [2] eb ae [2] c5 ae [2] fa b2 }

  condition:
    any of them
}