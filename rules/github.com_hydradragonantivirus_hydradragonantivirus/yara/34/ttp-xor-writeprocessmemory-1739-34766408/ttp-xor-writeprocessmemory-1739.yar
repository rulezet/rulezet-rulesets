rule TTP_XOR_WriteProcessMemory_1739 {
  strings:
    $key_1739 = { 40 4b [2] 72 69 [2] 74 5c [2] 5a 5c [2] 65 40 }

  condition:
    any of them
}