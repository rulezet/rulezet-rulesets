rule TTP_XOR_WriteProcessMemory_d82d {
  strings:
    $key_d82d = { 8f 5f [2] bd 7d [2] bb 48 [2] 95 48 [2] aa 54 }

  condition:
    any of them
}