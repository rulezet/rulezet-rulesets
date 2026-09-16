rule TTP_XOR_WriteProcessMemory_d801 {
  strings:
    $key_d801 = { 8f 73 [2] bd 51 [2] bb 64 [2] 95 64 [2] aa 78 }

  condition:
    any of them
}