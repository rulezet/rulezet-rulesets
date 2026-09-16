rule TTP_XOR_WriteProcessMemory_5486 {
  strings:
    $key_5486 = { 03 f4 [2] 31 d6 [2] 37 e3 [2] 19 e3 [2] 26 ff }

  condition:
    any of them
}