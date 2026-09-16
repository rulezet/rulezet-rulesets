rule TTP_XOR_WriteProcessMemory_d87a {
  strings:
    $key_d87a = { 8f 08 [2] bd 2a [2] bb 1f [2] 95 1f [2] aa 03 }

  condition:
    any of them
}