rule TTP_XOR_WriteProcessMemory_f311 {
  strings:
    $key_f311 = { a4 63 [2] 96 41 [2] 90 74 [2] be 74 [2] 81 68 }

  condition:
    any of them
}