rule TTP_XOR_WriteProcessMemory_d86f {
  strings:
    $key_d86f = { 8f 1d [2] bd 3f [2] bb 0a [2] 95 0a [2] aa 16 }

  condition:
    any of them
}