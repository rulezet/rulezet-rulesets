rule TTP_XOR_WriteProcessMemory_d81c {
  strings:
    $key_d81c = { 8f 6e [2] bd 4c [2] bb 79 [2] 95 79 [2] aa 65 }

  condition:
    any of them
}