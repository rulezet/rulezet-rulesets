rule TTP_XOR_WriteProcessMemory_1411 {
  strings:
    $key_1411 = { 43 63 [2] 71 41 [2] 77 74 [2] 59 74 [2] 66 68 }

  condition:
    any of them
}