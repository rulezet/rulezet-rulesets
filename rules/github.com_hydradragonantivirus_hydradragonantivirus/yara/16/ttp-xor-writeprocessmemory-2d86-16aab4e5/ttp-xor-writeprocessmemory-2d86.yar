rule TTP_XOR_WriteProcessMemory_2d86 {
  strings:
    $key_2d86 = { 7a f4 [2] 48 d6 [2] 4e e3 [2] 60 e3 [2] 5f ff }

  condition:
    any of them
}