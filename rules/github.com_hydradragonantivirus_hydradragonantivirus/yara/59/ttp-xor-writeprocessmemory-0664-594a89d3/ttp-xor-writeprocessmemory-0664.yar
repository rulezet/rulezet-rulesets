rule TTP_XOR_WriteProcessMemory_0664 {
  strings:
    $key_0664 = { 51 16 [2] 63 34 [2] 65 01 [2] 4b 01 [2] 74 1d }

  condition:
    any of them
}