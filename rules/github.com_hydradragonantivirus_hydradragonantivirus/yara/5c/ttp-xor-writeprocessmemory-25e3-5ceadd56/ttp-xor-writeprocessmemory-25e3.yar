rule TTP_XOR_WriteProcessMemory_25e3 {
  strings:
    $key_25e3 = { 72 91 [2] 40 b3 [2] 46 86 [2] 68 86 [2] 57 9a }

  condition:
    any of them
}