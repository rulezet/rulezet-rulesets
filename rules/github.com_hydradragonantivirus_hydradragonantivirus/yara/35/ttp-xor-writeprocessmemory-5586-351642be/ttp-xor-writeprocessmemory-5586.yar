rule TTP_XOR_WriteProcessMemory_5586 {
  strings:
    $key_5586 = { 02 f4 [2] 30 d6 [2] 36 e3 [2] 18 e3 [2] 27 ff }

  condition:
    any of them
}