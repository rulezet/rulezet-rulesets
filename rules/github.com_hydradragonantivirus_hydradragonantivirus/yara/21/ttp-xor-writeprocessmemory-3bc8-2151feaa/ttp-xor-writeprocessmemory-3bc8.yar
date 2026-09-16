rule TTP_XOR_WriteProcessMemory_3bc8 {
  strings:
    $key_3bc8 = { 6c ba [2] 5e 98 [2] 58 ad [2] 76 ad [2] 49 b1 }

  condition:
    any of them
}