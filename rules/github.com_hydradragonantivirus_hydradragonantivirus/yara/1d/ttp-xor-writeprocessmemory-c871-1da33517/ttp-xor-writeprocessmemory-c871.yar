rule TTP_XOR_WriteProcessMemory_c871 {
  strings:
    $key_c871 = { 9f 03 [2] ad 21 [2] ab 14 [2] 85 14 [2] ba 08 }

  condition:
    any of them
}