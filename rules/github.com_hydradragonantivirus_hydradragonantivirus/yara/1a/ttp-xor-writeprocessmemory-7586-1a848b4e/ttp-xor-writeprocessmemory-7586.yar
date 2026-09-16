rule TTP_XOR_WriteProcessMemory_7586 {
  strings:
    $key_7586 = { 22 f4 [2] 10 d6 [2] 16 e3 [2] 38 e3 [2] 07 ff }

  condition:
    any of them
}