rule TTP_XOR_WriteProcessMemory_0b59 {
  strings:
    $key_0b59 = { 5c 2b [2] 6e 09 [2] 68 3c [2] 46 3c [2] 79 20 }

  condition:
    any of them
}