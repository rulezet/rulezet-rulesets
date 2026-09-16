rule TTP_XOR_WriteProcessMemory_78c8 {
  strings:
    $key_78c8 = { 2f ba [2] 1d 98 [2] 1b ad [2] 35 ad [2] 0a b1 }

  condition:
    any of them
}