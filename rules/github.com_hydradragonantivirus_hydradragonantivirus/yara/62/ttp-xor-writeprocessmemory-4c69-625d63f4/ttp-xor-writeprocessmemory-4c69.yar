rule TTP_XOR_WriteProcessMemory_4c69 {
  strings:
    $key_4c69 = { 1b 1b [2] 29 39 [2] 2f 0c [2] 01 0c [2] 3e 10 }

  condition:
    any of them
}