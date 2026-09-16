rule TTP_XOR_WriteProcessMemory_51e3 {
  strings:
    $key_51e3 = { 06 91 [2] 34 b3 [2] 32 86 [2] 1c 86 [2] 23 9a }

  condition:
    any of them
}