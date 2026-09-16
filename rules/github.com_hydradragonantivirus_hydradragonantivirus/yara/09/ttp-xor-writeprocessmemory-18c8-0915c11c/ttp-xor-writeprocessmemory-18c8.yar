rule TTP_XOR_WriteProcessMemory_18c8 {
  strings:
    $key_18c8 = { 4f ba [2] 7d 98 [2] 7b ad [2] 55 ad [2] 6a b1 }

  condition:
    any of them
}