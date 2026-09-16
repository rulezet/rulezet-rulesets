rule TTP_XOR_WriteProcessMemory_1455 {
  strings:
    $key_1455 = { 43 27 [2] 71 05 [2] 77 30 [2] 59 30 [2] 66 2c }

  condition:
    any of them
}