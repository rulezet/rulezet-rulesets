rule TTP_XOR_WriteProcessMemory_e038 {
  strings:
    $key_e038 = { b7 4a [2] 85 68 [2] 83 5d [2] ad 5d [2] 92 41 }

  condition:
    any of them
}