rule TTP_XOR_WriteProcessMemory_7e69 {
  strings:
    $key_7e69 = { 29 1b [2] 1b 39 [2] 1d 0c [2] 33 0c [2] 0c 10 }

  condition:
    any of them
}