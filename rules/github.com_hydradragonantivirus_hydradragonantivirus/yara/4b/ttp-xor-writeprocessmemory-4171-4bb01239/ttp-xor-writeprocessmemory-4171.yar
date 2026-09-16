rule TTP_XOR_WriteProcessMemory_4171 {
  strings:
    $key_4171 = { 16 03 [2] 24 21 [2] 22 14 [2] 0c 14 [2] 33 08 }

  condition:
    any of them
}