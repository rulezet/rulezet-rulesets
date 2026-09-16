rule TTP_XOR_WriteProcessMemory_2471 {
  strings:
    $key_2471 = { 73 03 [2] 41 21 [2] 47 14 [2] 69 14 [2] 56 08 }

  condition:
    any of them
}