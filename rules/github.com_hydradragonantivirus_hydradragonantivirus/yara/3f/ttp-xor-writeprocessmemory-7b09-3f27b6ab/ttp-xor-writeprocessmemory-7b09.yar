rule TTP_XOR_WriteProcessMemory_7b09 {
  strings:
    $key_7b09 = { 2c 7b [2] 1e 59 [2] 18 6c [2] 36 6c [2] 09 70 }

  condition:
    any of them
}