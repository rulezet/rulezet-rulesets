rule TTP_XOR_WriteProcessMemory_75e3 {
  strings:
    $key_75e3 = { 22 91 [2] 10 b3 [2] 16 86 [2] 38 86 [2] 07 9a }

  condition:
    any of them
}