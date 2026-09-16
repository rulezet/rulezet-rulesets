rule TTP_XOR_WriteProcessMemory_6b18 {
  strings:
    $key_6b18 = { 3c 6a [2] 0e 48 [2] 08 7d [2] 26 7d [2] 19 61 }

  condition:
    any of them
}