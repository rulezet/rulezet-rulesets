rule TTP_XOR_WriteProcessMemory_0ac8 {
  strings:
    $key_0ac8 = { 5d ba [2] 6f 98 [2] 69 ad [2] 47 ad [2] 78 b1 }

  condition:
    any of them
}