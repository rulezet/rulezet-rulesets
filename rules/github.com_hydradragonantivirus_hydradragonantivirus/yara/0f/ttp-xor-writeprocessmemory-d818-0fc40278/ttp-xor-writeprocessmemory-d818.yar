rule TTP_XOR_WriteProcessMemory_d818 {
  strings:
    $key_d818 = { 8f 6a [2] bd 48 [2] bb 7d [2] 95 7d [2] aa 61 }

  condition:
    any of them
}