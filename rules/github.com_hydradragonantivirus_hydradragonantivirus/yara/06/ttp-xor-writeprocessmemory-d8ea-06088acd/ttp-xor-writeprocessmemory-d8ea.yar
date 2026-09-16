rule TTP_XOR_WriteProcessMemory_d8ea {
  strings:
    $key_d8ea = { 8f 98 [2] bd ba [2] bb 8f [2] 95 8f [2] aa 93 }

  condition:
    any of them
}