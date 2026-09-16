rule TTP_XOR_WriteProcessMemory_d8e8 {
  strings:
    $key_d8e8 = { 8f 9a [2] bd b8 [2] bb 8d [2] 95 8d [2] aa 91 }

  condition:
    any of them
}