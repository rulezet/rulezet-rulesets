rule TTP_XOR_WriteProcessMemory_4547 {
  strings:
    $key_4547 = { 12 35 [2] 20 17 [2] 26 22 [2] 08 22 [2] 37 3e }

  condition:
    any of them
}