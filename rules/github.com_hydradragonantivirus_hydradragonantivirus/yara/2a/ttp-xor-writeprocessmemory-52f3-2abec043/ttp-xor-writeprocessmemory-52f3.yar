rule TTP_XOR_WriteProcessMemory_52f3 {
  strings:
    $key_52f3 = { 05 81 [2] 37 a3 [2] 31 96 [2] 1f 96 [2] 20 8a }

  condition:
    any of them
}