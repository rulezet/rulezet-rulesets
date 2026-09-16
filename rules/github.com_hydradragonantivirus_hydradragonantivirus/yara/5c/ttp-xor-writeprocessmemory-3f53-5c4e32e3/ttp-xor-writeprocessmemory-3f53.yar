rule TTP_XOR_WriteProcessMemory_3f53 {
  strings:
    $key_3f53 = { 68 21 [2] 5a 03 [2] 5c 36 [2] 72 36 [2] 4d 2a }

  condition:
    any of them
}