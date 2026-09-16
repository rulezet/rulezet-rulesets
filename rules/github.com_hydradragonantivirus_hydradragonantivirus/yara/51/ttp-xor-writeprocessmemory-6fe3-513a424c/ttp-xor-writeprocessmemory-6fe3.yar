rule TTP_XOR_WriteProcessMemory_6fe3 {
  strings:
    $key_6fe3 = { 38 91 [2] 0a b3 [2] 0c 86 [2] 22 86 [2] 1d 9a }

  condition:
    any of them
}