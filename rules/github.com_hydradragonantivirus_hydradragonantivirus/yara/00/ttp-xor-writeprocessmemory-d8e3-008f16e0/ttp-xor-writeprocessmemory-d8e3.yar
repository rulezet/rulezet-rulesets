rule TTP_XOR_WriteProcessMemory_d8e3 {
  strings:
    $key_d8e3 = { 8f 91 [2] bd b3 [2] bb 86 [2] 95 86 [2] aa 9a }

  condition:
    any of them
}