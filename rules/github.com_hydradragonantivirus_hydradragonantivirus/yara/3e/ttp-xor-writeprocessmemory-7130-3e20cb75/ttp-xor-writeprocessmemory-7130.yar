rule TTP_XOR_WriteProcessMemory_7130 {
  strings:
    $key_7130 = { 26 42 [2] 14 60 [2] 12 55 [2] 3c 55 [2] 03 49 }

  condition:
    any of them
}