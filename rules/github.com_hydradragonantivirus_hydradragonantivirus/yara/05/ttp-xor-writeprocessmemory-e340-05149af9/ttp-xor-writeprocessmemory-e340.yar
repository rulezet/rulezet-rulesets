rule TTP_XOR_WriteProcessMemory_e340 {
  strings:
    $key_e340 = { b4 32 [2] 86 10 [2] 80 25 [2] ae 25 [2] 91 39 }

  condition:
    any of them
}