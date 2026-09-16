rule TTP_XOR_WriteProcessMemory_3259 {
  strings:
    $key_3259 = { 65 2b [2] 57 09 [2] 51 3c [2] 7f 3c [2] 40 20 }

  condition:
    any of them
}