rule TTP_XOR_WriteProcessMemory_5fe3 {
  strings:
    $key_5fe3 = { 08 91 [2] 3a b3 [2] 3c 86 [2] 12 86 [2] 2d 9a }

  condition:
    any of them
}