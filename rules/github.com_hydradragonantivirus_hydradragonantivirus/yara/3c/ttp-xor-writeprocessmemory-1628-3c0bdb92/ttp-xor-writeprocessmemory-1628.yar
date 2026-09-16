rule TTP_XOR_WriteProcessMemory_1628 {
  strings:
    $key_1628 = { 41 5a [2] 73 78 [2] 75 4d [2] 5b 4d [2] 64 51 }

  condition:
    any of them
}