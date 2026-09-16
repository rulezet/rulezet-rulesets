rule TTP_XOR_WriteProcessMemory_5be3 {
  strings:
    $key_5be3 = { 0c 91 [2] 3e b3 [2] 38 86 [2] 16 86 [2] 29 9a }

  condition:
    any of them
}