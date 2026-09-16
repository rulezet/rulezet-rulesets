rule TTP_XOR_WriteProcessMemory_02f2 {
  strings:
    $key_02f2 = { 55 80 [2] 67 a2 [2] 61 97 [2] 4f 97 [2] 70 8b }

  condition:
    any of them
}