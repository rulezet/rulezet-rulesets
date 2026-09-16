rule TTP_XOR_WriteProcessMemory_4218 {
  strings:
    $key_4218 = { 15 6a [2] 27 48 [2] 21 7d [2] 0f 7d [2] 30 61 }

  condition:
    any of them
}