rule TTP_XOR_WriteProcessMemory_4104 {
  strings:
    $key_4104 = { 16 76 [2] 24 54 [2] 22 61 [2] 0c 61 [2] 33 7d }

  condition:
    any of them
}