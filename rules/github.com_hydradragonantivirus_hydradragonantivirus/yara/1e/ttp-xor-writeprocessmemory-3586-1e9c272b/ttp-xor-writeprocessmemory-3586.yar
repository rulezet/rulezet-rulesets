rule TTP_XOR_WriteProcessMemory_3586 {
  strings:
    $key_3586 = { 62 f4 [2] 50 d6 [2] 56 e3 [2] 78 e3 [2] 47 ff }

  condition:
    any of them
}