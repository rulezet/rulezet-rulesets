rule TTP_XOR_WriteProcessMemory_5de3 {
  strings:
    $key_5de3 = { 0a 91 [2] 38 b3 [2] 3e 86 [2] 10 86 [2] 2f 9a }

  condition:
    any of them
}