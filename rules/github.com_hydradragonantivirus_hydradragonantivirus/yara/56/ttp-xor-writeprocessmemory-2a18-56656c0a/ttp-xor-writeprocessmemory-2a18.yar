rule TTP_XOR_WriteProcessMemory_2a18 {
  strings:
    $key_2a18 = { 7d 6a [2] 4f 48 [2] 49 7d [2] 67 7d [2] 58 61 }

  condition:
    any of them
}