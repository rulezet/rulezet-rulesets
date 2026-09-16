rule TTP_XOR_WriteProcessMemory_0b19 {
  strings:
    $key_0b19 = { 5c 6b [2] 6e 49 [2] 68 7c [2] 46 7c [2] 79 60 }

  condition:
    any of them
}