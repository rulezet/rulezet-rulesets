rule TTP_XOR_WriteProcessMemory_c808 {
  strings:
    $key_c808 = { 9f 7a [2] ad 58 [2] ab 6d [2] 85 6d [2] ba 71 }

  condition:
    any of them
}