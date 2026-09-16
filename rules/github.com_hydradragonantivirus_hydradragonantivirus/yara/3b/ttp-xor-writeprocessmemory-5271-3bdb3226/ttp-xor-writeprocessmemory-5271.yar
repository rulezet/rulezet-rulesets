rule TTP_XOR_WriteProcessMemory_5271 {
  strings:
    $key_5271 = { 05 03 [2] 37 21 [2] 31 14 [2] 1f 14 [2] 20 08 }

  condition:
    any of them
}