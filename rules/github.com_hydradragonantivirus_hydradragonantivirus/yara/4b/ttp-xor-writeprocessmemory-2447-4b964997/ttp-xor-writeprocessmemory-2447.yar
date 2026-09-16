rule TTP_XOR_WriteProcessMemory_2447 {
  strings:
    $key_2447 = { 73 35 [2] 41 17 [2] 47 22 [2] 69 22 [2] 56 3e }

  condition:
    any of them
}