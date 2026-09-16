rule TTP_XOR_WriteProcessMemory_6e47 {
  strings:
    $key_6e47 = { 39 35 [2] 0b 17 [2] 0d 22 [2] 23 22 [2] 1c 3e }

  condition:
    any of them
}