rule TTP_XOR_WriteProcessMemory_30e3 {
  strings:
    $key_30e3 = { 67 91 [2] 55 b3 [2] 53 86 [2] 7d 86 [2] 42 9a }

  condition:
    any of them
}