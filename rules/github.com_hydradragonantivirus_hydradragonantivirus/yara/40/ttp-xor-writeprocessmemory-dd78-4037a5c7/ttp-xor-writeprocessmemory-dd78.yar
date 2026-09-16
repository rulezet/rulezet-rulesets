rule TTP_XOR_WriteProcessMemory_dd78 {
  strings:
    $key_dd78 = { 8a 0a [2] b8 28 [2] be 1d [2] 90 1d [2] af 01 }

  condition:
    any of them
}