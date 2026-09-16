rule TTP_XOR_WriteProcessMemory_08c8 {
  strings:
    $key_08c8 = { 5f ba [2] 6d 98 [2] 6b ad [2] 45 ad [2] 7a b1 }

  condition:
    any of them
}