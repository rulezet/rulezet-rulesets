rule TTP_XOR_WriteProcessMemory_0b39 {
  strings:
    $key_0b39 = { 5c 4b [2] 6e 69 [2] 68 5c [2] 46 5c [2] 79 40 }

  condition:
    any of them
}