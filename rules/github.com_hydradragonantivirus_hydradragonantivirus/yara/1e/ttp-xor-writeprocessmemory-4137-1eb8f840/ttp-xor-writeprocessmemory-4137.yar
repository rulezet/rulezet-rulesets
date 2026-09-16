rule TTP_XOR_WriteProcessMemory_4137 {
  strings:
    $key_4137 = { 16 45 [2] 24 67 [2] 22 52 [2] 0c 52 [2] 33 4e }

  condition:
    any of them
}