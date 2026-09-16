rule TTP_XOR_WriteProcessMemory_0034 {
  strings:
    $key_0034 = { 57 46 [2] 65 64 [2] 63 51 [2] 4d 51 [2] 72 4d }

  condition:
    any of them
}