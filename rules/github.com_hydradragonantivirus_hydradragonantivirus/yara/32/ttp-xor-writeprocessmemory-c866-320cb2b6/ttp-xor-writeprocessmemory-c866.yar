rule TTP_XOR_WriteProcessMemory_c866 {
  strings:
    $key_c866 = { 9f 14 [2] ad 36 [2] ab 03 [2] 85 03 [2] ba 1f }

  condition:
    any of them
}