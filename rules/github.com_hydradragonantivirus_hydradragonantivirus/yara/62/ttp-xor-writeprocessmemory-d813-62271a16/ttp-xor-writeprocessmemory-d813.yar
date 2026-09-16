rule TTP_XOR_WriteProcessMemory_d813 {
  strings:
    $key_d813 = { 8f 61 [2] bd 43 [2] bb 76 [2] 95 76 [2] aa 6a }

  condition:
    any of them
}