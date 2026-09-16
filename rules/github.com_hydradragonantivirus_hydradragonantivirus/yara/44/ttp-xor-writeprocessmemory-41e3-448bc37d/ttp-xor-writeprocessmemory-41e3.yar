rule TTP_XOR_WriteProcessMemory_41e3 {
  strings:
    $key_41e3 = { 16 91 [2] 24 b3 [2] 22 86 [2] 0c 86 [2] 33 9a }

  condition:
    any of them
}