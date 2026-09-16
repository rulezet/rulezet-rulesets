rule TTP_XOR_WriteProcessMemory_6d74 {
  strings:
    $key_6d74 = { 3a 06 [2] 08 24 [2] 0e 11 [2] 20 11 [2] 1f 0d }

  condition:
    any of them
}