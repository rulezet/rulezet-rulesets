rule TTP_XOR_WriteProcessMemory_1d09 {
  strings:
    $key_1d09 = { 4a 7b [2] 78 59 [2] 7e 6c [2] 50 6c [2] 6f 70 }

  condition:
    any of them
}