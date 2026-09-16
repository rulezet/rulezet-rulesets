rule TTP_XOR_WriteProcessMemory_1738 {
  strings:
    $key_1738 = { 40 4a [2] 72 68 [2] 74 5d [2] 5a 5d [2] 65 41 }

  condition:
    any of them
}