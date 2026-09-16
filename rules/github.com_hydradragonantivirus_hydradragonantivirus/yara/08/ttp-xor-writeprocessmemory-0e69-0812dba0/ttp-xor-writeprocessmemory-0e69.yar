rule TTP_XOR_WriteProcessMemory_0e69 {
  strings:
    $key_0e69 = { 59 1b [2] 6b 39 [2] 6d 0c [2] 43 0c [2] 7c 10 }

  condition:
    any of them
}