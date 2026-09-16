rule TTP_XOR_WriteProcessMemory_5bc8 {
  strings:
    $key_5bc8 = { 0c ba [2] 3e 98 [2] 38 ad [2] 16 ad [2] 29 b1 }

  condition:
    any of them
}