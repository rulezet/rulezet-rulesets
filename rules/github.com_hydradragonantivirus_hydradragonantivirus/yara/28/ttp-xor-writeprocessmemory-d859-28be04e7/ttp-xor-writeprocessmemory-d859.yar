rule TTP_XOR_WriteProcessMemory_d859 {
  strings:
    $key_d859 = { 8f 2b [2] bd 09 [2] bb 3c [2] 95 3c [2] aa 20 }

  condition:
    any of them
}