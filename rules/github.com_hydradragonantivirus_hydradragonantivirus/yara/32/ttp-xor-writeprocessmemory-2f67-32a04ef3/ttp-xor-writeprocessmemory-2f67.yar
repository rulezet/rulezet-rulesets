rule TTP_XOR_WriteProcessMemory_2f67 {
  strings:
    $key_2f67 = { 78 15 [2] 4a 37 [2] 4c 02 [2] 62 02 [2] 5d 1e }

  condition:
    any of them
}