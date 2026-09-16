rule TTP_XOR_WriteProcessMemory_1486 {
  strings:
    $key_1486 = { 43 f4 [2] 71 d6 [2] 77 e3 [2] 59 e3 [2] 66 ff }

  condition:
    any of them
}