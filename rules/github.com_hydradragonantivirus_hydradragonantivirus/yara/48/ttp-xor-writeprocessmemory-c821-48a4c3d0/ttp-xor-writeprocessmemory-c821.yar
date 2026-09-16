rule TTP_XOR_WriteProcessMemory_c821 {
  strings:
    $key_c821 = { 9f 53 [2] ad 71 [2] ab 44 [2] 85 44 [2] ba 58 }

  condition:
    any of them
}