rule TTP_XOR_WriteProcessMemory_d80a {
  strings:
    $key_d80a = { 8f 78 [2] bd 5a [2] bb 6f [2] 95 6f [2] aa 73 }

  condition:
    any of them
}