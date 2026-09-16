rule TTP_XOR_WriteProcessMemory_68f4 {
  strings:
    $key_68f4 = { 3f 86 [2] 0d a4 [2] 0b 91 [2] 25 91 [2] 1a 8d }

  condition:
    any of them
}