rule TTP_XOR_WriteProcessMemory_6e69 {
  strings:
    $key_6e69 = { 39 1b [2] 0b 39 [2] 0d 0c [2] 23 0c [2] 1c 10 }

  condition:
    any of them
}