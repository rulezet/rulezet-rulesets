rule TTP_XOR_WriteProcessMemory_75f4 {
  strings:
    $key_75f4 = { 22 86 [2] 10 a4 [2] 16 91 [2] 38 91 [2] 07 8d }

  condition:
    any of them
}