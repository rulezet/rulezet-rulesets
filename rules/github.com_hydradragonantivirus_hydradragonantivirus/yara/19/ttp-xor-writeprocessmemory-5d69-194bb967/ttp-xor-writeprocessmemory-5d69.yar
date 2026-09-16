rule TTP_XOR_WriteProcessMemory_5d69 {
  strings:
    $key_5d69 = { 0a 1b [2] 38 39 [2] 3e 0c [2] 10 0c [2] 2f 10 }

  condition:
    any of them
}