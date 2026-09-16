rule TTP_XOR_WriteProcessMemory_7777 {
  strings:
    $key_7777 = { 20 05 [2] 12 27 [2] 14 12 [2] 3a 12 [2] 05 0e }

  condition:
    any of them
}