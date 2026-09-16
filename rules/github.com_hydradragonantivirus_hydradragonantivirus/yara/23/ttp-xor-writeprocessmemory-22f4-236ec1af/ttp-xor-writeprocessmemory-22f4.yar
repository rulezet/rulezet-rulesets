rule TTP_XOR_WriteProcessMemory_22f4 {
  strings:
    $key_22f4 = { 75 86 [2] 47 a4 [2] 41 91 [2] 6f 91 [2] 50 8d }

  condition:
    any of them
}