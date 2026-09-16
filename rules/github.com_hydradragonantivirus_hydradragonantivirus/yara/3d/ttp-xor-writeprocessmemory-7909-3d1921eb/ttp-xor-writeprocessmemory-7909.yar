rule TTP_XOR_WriteProcessMemory_7909 {
  strings:
    $key_7909 = { 2e 7b [2] 1c 59 [2] 1a 6c [2] 34 6c [2] 0b 70 }

  condition:
    any of them
}