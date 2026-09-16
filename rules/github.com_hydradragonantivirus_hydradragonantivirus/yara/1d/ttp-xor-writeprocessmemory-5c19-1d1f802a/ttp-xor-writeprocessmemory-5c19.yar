rule TTP_XOR_WriteProcessMemory_5c19 {
  strings:
    $key_5c19 = { 0b 6b [2] 39 49 [2] 3f 7c [2] 11 7c [2] 2e 60 }

  condition:
    any of them
}