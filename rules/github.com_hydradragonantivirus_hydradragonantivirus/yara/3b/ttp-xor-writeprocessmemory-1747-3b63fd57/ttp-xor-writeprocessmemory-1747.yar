rule TTP_XOR_WriteProcessMemory_1747 {
  strings:
    $key_1747 = { 40 35 [2] 72 17 [2] 74 22 [2] 5a 22 [2] 65 3e }

  condition:
    any of them
}