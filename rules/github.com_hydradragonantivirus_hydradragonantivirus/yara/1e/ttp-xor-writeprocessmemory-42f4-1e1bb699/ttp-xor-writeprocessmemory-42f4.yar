rule TTP_XOR_WriteProcessMemory_42f4 {
  strings:
    $key_42f4 = { 15 86 [2] 27 a4 [2] 21 91 [2] 0f 91 [2] 30 8d }

  condition:
    any of them
}