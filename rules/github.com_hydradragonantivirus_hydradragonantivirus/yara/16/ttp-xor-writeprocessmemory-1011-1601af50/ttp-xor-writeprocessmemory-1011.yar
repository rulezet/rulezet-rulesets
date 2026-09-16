rule TTP_XOR_WriteProcessMemory_1011 {
  strings:
    $key_1011 = { 47 63 [2] 75 41 [2] 73 74 [2] 5d 74 [2] 62 68 }

  condition:
    any of them
}