rule TTP_XOR_WriteProcessMemory_3f67 {
  strings:
    $key_3f67 = { 68 15 [2] 5a 37 [2] 5c 02 [2] 72 02 [2] 4d 1e }

  condition:
    any of them
}