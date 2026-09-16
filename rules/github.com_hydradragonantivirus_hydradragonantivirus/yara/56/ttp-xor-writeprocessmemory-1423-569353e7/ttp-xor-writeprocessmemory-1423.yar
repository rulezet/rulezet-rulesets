rule TTP_XOR_WriteProcessMemory_1423 {
  strings:
    $key_1423 = { 43 51 [2] 71 73 [2] 77 46 [2] 59 46 [2] 66 5a }

  condition:
    any of them
}