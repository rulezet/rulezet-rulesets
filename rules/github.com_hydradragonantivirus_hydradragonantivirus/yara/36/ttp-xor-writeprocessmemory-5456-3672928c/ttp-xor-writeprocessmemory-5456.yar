rule TTP_XOR_WriteProcessMemory_5456 {
  strings:
    $key_5456 = { 03 24 [2] 31 06 [2] 37 33 [2] 19 33 [2] 26 2f }

  condition:
    any of them
}