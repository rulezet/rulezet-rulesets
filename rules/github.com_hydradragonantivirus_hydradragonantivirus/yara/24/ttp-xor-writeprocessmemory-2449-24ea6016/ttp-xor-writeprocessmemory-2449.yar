rule TTP_XOR_WriteProcessMemory_2449 {
  strings:
    $key_2449 = { 73 3b [2] 41 19 [2] 47 2c [2] 69 2c [2] 56 30 }

  condition:
    any of them
}