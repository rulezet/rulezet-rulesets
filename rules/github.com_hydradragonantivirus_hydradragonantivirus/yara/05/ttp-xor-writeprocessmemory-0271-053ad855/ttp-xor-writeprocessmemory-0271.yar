rule TTP_XOR_WriteProcessMemory_0271 {
  strings:
    $key_0271 = { 55 03 [2] 67 21 [2] 61 14 [2] 4f 14 [2] 70 08 }

  condition:
    any of them
}