rule TTP_XOR_WriteProcessMemory_5669 {
  strings:
    $key_5669 = { 01 1b [2] 33 39 [2] 35 0c [2] 1b 0c [2] 24 10 }

  condition:
    any of them
}