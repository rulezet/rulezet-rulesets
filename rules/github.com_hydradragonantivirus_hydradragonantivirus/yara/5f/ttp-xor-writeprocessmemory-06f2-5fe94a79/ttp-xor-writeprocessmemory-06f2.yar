rule TTP_XOR_WriteProcessMemory_06f2 {
  strings:
    $key_06f2 = { 51 80 [2] 63 a2 [2] 65 97 [2] 4b 97 [2] 74 8b }

  condition:
    any of them
}