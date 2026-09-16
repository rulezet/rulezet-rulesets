rule TTP_XOR_WriteProcessMemory_0969 {
  strings:
    $key_0969 = { 5e 1b [2] 6c 39 [2] 6a 0c [2] 44 0c [2] 7b 10 }

  condition:
    any of them
}