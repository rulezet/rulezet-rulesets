rule TTP_XOR_WriteProcessMemory_d819 {
  strings:
    $key_d819 = { 8f 6b [2] bd 49 [2] bb 7c [2] 95 7c [2] aa 60 }

  condition:
    any of them
}