rule TTP_XOR_WriteProcessMemory_4f31 {
  strings:
    $key_4f31 = { 18 43 [2] 2a 61 [2] 2c 54 [2] 02 54 [2] 3d 48 }

  condition:
    any of them
}