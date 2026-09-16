rule TTP_XOR_WriteProcessMemory_17f4 {
  strings:
    $key_17f4 = { 40 86 [2] 72 a4 [2] 74 91 [2] 5a 91 [2] 65 8d }

  condition:
    any of them
}