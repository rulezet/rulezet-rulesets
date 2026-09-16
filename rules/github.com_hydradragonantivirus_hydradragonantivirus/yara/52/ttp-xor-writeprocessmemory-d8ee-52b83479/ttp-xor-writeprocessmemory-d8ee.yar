rule TTP_XOR_WriteProcessMemory_d8ee {
  strings:
    $key_d8ee = { 8f 9c [2] bd be [2] bb 8b [2] 95 8b [2] aa 97 }

  condition:
    any of them
}