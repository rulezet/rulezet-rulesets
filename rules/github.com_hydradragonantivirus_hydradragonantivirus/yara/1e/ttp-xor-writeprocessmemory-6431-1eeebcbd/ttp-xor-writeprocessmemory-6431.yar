rule TTP_XOR_WriteProcessMemory_6431 {
  strings:
    $key_6431 = { 33 43 [2] 01 61 [2] 07 54 [2] 29 54 [2] 16 48 }

  condition:
    any of them
}