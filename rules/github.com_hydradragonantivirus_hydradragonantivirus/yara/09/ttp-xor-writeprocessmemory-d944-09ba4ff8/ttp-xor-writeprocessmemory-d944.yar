rule TTP_XOR_WriteProcessMemory_d944 {
  strings:
    $key_d944 = { 8e 36 [2] bc 14 [2] ba 21 [2] 94 21 [2] ab 3d }

  condition:
    any of them
}