rule TTP_XOR_WriteProcessMemory_5647 {
  strings:
    $key_5647 = { 01 35 [2] 33 17 [2] 35 22 [2] 1b 22 [2] 24 3e }

  condition:
    any of them
}