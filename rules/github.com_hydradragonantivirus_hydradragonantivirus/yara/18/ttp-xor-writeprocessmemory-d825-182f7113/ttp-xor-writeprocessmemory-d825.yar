rule TTP_XOR_WriteProcessMemory_d825 {
  strings:
    $key_d825 = { 8f 57 [2] bd 75 [2] bb 40 [2] 95 40 [2] aa 5c }

  condition:
    any of them
}