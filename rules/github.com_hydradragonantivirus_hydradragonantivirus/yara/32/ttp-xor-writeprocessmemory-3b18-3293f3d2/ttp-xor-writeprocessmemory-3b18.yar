rule TTP_XOR_WriteProcessMemory_3b18 {
  strings:
    $key_3b18 = { 6c 6a [2] 5e 48 [2] 58 7d [2] 76 7d [2] 49 61 }

  condition:
    any of them
}