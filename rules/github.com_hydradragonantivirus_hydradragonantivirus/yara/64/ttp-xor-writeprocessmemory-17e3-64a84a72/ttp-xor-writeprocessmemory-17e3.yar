rule TTP_XOR_WriteProcessMemory_17e3 {
  strings:
    $key_17e3 = { 40 91 [2] 72 b3 [2] 74 86 [2] 5a 86 [2] 65 9a }

  condition:
    any of them
}