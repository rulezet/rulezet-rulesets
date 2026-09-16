rule TTP_XOR_WriteProcessMemory_7344 {
  strings:
    $key_7344 = { 24 36 [2] 16 14 [2] 10 21 [2] 3e 21 [2] 01 3d }

  condition:
    any of them
}