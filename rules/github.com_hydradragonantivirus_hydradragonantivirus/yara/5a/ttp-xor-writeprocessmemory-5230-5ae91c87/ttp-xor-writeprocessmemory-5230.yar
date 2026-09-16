rule TTP_XOR_WriteProcessMemory_5230 {
  strings:
    $key_5230 = { 05 42 [2] 37 60 [2] 31 55 [2] 1f 55 [2] 20 49 }

  condition:
    any of them
}