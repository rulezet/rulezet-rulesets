rule TTP_XOR_WriteProcessMemory_0d86 {
  strings:
    $key_0d86 = { 5a f4 [2] 68 d6 [2] 6e e3 [2] 40 e3 [2] 7f ff }

  condition:
    any of them
}