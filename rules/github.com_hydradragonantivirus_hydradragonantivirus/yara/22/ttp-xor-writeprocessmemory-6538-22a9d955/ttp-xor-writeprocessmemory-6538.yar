rule TTP_XOR_WriteProcessMemory_6538 {
  strings:
    $key_6538 = { 32 4a [2] 00 68 [2] 06 5d [2] 28 5d [2] 17 41 }

  condition:
    any of them
}