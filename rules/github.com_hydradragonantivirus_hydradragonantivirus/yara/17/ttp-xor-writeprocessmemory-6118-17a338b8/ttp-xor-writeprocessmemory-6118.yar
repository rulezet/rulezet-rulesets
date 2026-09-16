rule TTP_XOR_WriteProcessMemory_6118 {
  strings:
    $key_6118 = { 36 6a [2] 04 48 [2] 02 7d [2] 2c 7d [2] 13 61 }

  condition:
    any of them
}