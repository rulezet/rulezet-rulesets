rule TTP_XOR_WriteProcessMemory_6447 {
  strings:
    $key_6447 = { 33 35 [2] 01 17 [2] 07 22 [2] 29 22 [2] 16 3e }

  condition:
    any of them
}