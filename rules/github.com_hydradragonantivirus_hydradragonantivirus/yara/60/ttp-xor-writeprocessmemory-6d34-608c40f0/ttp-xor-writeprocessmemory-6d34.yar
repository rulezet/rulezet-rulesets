rule TTP_XOR_WriteProcessMemory_6d34 {
  strings:
    $key_6d34 = { 3a 46 [2] 08 64 [2] 0e 51 [2] 20 51 [2] 1f 4d }

  condition:
    any of them
}