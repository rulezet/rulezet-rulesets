rule TTP_XOR_WriteProcessMemory_1ce3 {
  strings:
    $key_1ce3 = { 4b 91 [2] 79 b3 [2] 7f 86 [2] 51 86 [2] 6e 9a }

  condition:
    any of them
}