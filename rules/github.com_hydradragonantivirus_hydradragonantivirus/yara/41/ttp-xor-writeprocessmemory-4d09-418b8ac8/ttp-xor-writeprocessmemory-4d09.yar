rule TTP_XOR_WriteProcessMemory_4d09 {
  strings:
    $key_4d09 = { 1a 7b [2] 28 59 [2] 2e 6c [2] 00 6c [2] 3f 70 }

  condition:
    any of them
}