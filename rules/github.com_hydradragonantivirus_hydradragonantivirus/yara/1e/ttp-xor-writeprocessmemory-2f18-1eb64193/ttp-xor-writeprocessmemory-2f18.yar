rule TTP_XOR_WriteProcessMemory_2f18 {
  strings:
    $key_2f18 = { 78 6a [2] 4a 48 [2] 4c 7d [2] 62 7d [2] 5d 61 }

  condition:
    any of them
}