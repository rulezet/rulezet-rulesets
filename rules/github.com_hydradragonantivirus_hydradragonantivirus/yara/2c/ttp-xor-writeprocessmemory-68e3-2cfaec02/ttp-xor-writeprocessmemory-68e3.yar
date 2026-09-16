rule TTP_XOR_WriteProcessMemory_68e3 {
  strings:
    $key_68e3 = { 3f 91 [2] 0d b3 [2] 0b 86 [2] 25 86 [2] 1a 9a }

  condition:
    any of them
}