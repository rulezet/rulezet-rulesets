rule TTP_XOR_WriteProcessMemory_6bc8 {
  strings:
    $key_6bc8 = { 3c ba [2] 0e 98 [2] 08 ad [2] 26 ad [2] 19 b1 }

  condition:
    any of them
}