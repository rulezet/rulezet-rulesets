rule TTP_XOR_WriteProcessMemory_62c8 {
  strings:
    $key_62c8 = { 35 ba [2] 07 98 [2] 01 ad [2] 2f ad [2] 10 b1 }

  condition:
    any of them
}