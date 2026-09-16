rule TTP_XOR_WriteProcessMemory_0022 {
  strings:
    $key_0022 = { 57 50 [2] 65 72 [2] 63 47 [2] 4d 47 [2] 72 5b }

  condition:
    any of them
}