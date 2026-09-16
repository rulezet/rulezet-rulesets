rule TTP_XOR_WriteProcessMemory_1007 {
  strings:
    $key_1007 = { 47 75 [2] 75 57 [2] 73 62 [2] 5d 62 [2] 62 7e }

  condition:
    any of them
}