rule TTP_XOR_WriteProcessMemory_4151 {
  strings:
    $key_4151 = { 16 23 [2] 24 01 [2] 22 34 [2] 0c 34 [2] 33 28 }

  condition:
    any of them
}