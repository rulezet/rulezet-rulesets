rule TTP_XOR_WriteProcessMemory_0369 {
  strings:
    $key_0369 = { 54 1b [2] 66 39 [2] 60 0c [2] 4e 0c [2] 71 10 }

  condition:
    any of them
}