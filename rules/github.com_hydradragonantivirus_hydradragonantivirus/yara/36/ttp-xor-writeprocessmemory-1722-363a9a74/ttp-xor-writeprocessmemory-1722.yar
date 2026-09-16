rule TTP_XOR_WriteProcessMemory_1722 {
  strings:
    $key_1722 = { 40 50 [2] 72 72 [2] 74 47 [2] 5a 47 [2] 65 5b }

  condition:
    any of them
}