rule TTP_XOR_WriteProcessMemory_5b11 {
  strings:
    $key_5b11 = { 0c 63 [2] 3e 41 [2] 38 74 [2] 16 74 [2] 29 68 }

  condition:
    any of them
}