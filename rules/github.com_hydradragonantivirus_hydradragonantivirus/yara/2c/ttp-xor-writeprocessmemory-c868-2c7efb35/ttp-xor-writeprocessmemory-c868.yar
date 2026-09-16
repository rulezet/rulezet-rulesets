rule TTP_XOR_WriteProcessMemory_c868 {
  strings:
    $key_c868 = { 9f 1a [2] ad 38 [2] ab 0d [2] 85 0d [2] ba 11 }

  condition:
    any of them
}