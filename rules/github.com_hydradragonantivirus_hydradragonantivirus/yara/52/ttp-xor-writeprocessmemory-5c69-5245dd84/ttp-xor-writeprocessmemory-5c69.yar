rule TTP_XOR_WriteProcessMemory_5c69 {
  strings:
    $key_5c69 = { 0b 1b [2] 39 39 [2] 3f 0c [2] 11 0c [2] 2e 10 }

  condition:
    any of them
}