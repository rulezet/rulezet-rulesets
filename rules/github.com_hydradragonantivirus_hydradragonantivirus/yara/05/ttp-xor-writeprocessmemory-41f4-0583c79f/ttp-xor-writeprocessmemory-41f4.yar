rule TTP_XOR_WriteProcessMemory_41f4 {
  strings:
    $key_41f4 = { 16 86 [2] 24 a4 [2] 22 91 [2] 0c 91 [2] 33 8d }

  condition:
    any of them
}