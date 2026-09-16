rule TTP_XOR_WriteProcessMemory_5b69 {
  strings:
    $key_5b69 = { 0c 1b [2] 3e 39 [2] 38 0c [2] 16 0c [2] 29 10 }

  condition:
    any of them
}