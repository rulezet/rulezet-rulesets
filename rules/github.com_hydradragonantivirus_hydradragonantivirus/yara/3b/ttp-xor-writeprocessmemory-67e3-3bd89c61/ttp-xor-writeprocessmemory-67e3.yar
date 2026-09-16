rule TTP_XOR_WriteProcessMemory_67e3 {
  strings:
    $key_67e3 = { 30 91 [2] 02 b3 [2] 04 86 [2] 2a 86 [2] 15 9a }

  condition:
    any of them
}