rule TTP_XOR_WriteProcessMemory_fcc8 {
  strings:
    $key_fcc8 = { ab ba [2] 99 98 [2] 9f ad [2] b1 ad [2] 8e b1 }

  condition:
    any of them
}