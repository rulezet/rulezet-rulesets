rule TTP_XOR_WriteProcessMemory_74e3 {
  strings:
    $key_74e3 = { 23 91 [2] 11 b3 [2] 17 86 [2] 39 86 [2] 06 9a }

  condition:
    any of them
}