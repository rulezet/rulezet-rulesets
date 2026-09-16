rule TTP_XOR_WriteProcessMemory_3679 {
  strings:
    $key_3679 = { 61 0b [2] 53 29 [2] 55 1c [2] 7b 1c [2] 44 00 }

  condition:
    any of them
}