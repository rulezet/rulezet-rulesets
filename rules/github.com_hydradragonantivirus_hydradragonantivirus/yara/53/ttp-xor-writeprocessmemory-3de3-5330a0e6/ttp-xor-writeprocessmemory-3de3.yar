rule TTP_XOR_WriteProcessMemory_3de3 {
  strings:
    $key_3de3 = { 6a 91 [2] 58 b3 [2] 5e 86 [2] 70 86 [2] 4f 9a }

  condition:
    any of them
}