rule TTP_XOR_WriteProcessMemory_d85a {
  strings:
    $key_d85a = { 8f 28 [2] bd 0a [2] bb 3f [2] 95 3f [2] aa 23 }

  condition:
    any of them
}