rule TTP_XOR_WriteProcessMemory_3f07 {
  strings:
    $key_3f07 = { 68 75 [2] 5a 57 [2] 5c 62 [2] 72 62 [2] 4d 7e }

  condition:
    any of them
}