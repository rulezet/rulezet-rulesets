rule TTP_XOR_WriteProcessMemory_16e3 {
  strings:
    $key_16e3 = { 41 91 [2] 73 b3 [2] 75 86 [2] 5b 86 [2] 64 9a }

  condition:
    any of them
}