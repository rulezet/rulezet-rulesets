rule TTP_XOR_WriteProcessMemory_06e3 {
  strings:
    $key_06e3 = { 51 91 [2] 63 b3 [2] 65 86 [2] 4b 86 [2] 74 9a }

  condition:
    any of them
}