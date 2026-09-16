rule TTP_XOR_WriteProcessMemory_3404 {
  strings:
    $key_3404 = { 63 76 [2] 51 54 [2] 57 61 [2] 79 61 [2] 46 7d }

  condition:
    any of them
}