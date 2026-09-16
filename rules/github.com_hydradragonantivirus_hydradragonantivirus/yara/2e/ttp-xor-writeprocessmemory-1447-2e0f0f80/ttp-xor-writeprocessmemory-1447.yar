rule TTP_XOR_WriteProcessMemory_1447 {
  strings:
    $key_1447 = { 43 35 [2] 71 17 [2] 77 22 [2] 59 22 [2] 66 3e }

  condition:
    any of them
}