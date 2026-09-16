rule TTP_XOR_WriteProcessMemory_d8c8 {
  strings:
    $key_d8c8 = { 8f ba [2] bd 98 [2] bb ad [2] 95 ad [2] aa b1 }

  condition:
    any of them
}