rule TTP_XOR_WriteProcessMemory_d82f {
  strings:
    $key_d82f = { 8f 5d [2] bd 7f [2] bb 4a [2] 95 4a [2] aa 56 }

  condition:
    any of them
}