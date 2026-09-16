rule TTP_XOR_WriteProcessMemory_3e49 {
  strings:
    $key_3e49 = { 69 3b [2] 5b 19 [2] 5d 2c [2] 73 2c [2] 4c 30 }

  condition:
    any of them
}