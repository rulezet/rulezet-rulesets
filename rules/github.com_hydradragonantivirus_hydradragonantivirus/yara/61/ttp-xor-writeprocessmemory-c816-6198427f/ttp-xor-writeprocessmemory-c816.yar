rule TTP_XOR_WriteProcessMemory_c816 {
  strings:
    $key_c816 = { 9f 64 [2] ad 46 [2] ab 73 [2] 85 73 [2] ba 6f }

  condition:
    any of them
}