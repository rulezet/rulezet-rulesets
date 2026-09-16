rule TTP_XOR_WriteProcessMemory_5139 {
  strings:
    $key_5139 = { 06 4b [2] 34 69 [2] 32 5c [2] 1c 5c [2] 23 40 }

  condition:
    any of them
}