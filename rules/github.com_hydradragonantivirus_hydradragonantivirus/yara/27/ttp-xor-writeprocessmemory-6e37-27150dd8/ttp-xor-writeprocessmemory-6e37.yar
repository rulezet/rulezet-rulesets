rule TTP_XOR_WriteProcessMemory_6e37 {
  strings:
    $key_6e37 = { 39 45 [2] 0b 67 [2] 0d 52 [2] 23 52 [2] 1c 4e }

  condition:
    any of them
}