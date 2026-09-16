rule TTP_XOR_WriteProcessMemory_13f4 {
  strings:
    $key_13f4 = { 44 86 [2] 76 a4 [2] 70 91 [2] 5e 91 [2] 61 8d }

  condition:
    any of them
}