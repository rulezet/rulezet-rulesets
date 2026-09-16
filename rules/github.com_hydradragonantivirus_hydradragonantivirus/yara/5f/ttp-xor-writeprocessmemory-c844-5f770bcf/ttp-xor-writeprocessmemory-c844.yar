rule TTP_XOR_WriteProcessMemory_c844 {
  strings:
    $key_c844 = { 9f 36 [2] ad 14 [2] ab 21 [2] 85 21 [2] ba 3d }

  condition:
    any of them
}