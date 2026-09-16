rule TTP_XOR_WriteProcessMemory_38c8 {
  strings:
    $key_38c8 = { 6f ba [2] 5d 98 [2] 5b ad [2] 75 ad [2] 4a b1 }

  condition:
    any of them
}