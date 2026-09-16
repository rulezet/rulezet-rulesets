rule TTP_XOR_WriteProcessMemory_5171 {
  strings:
    $key_5171 = { 06 03 [2] 34 21 [2] 32 14 [2] 1c 14 [2] 23 08 }

  condition:
    any of them
}