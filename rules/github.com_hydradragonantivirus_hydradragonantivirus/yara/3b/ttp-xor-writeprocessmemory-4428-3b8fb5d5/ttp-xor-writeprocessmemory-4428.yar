rule TTP_XOR_WriteProcessMemory_4428 {
  strings:
    $key_4428 = { 13 5a [2] 21 78 [2] 27 4d [2] 09 4d [2] 36 51 }

  condition:
    any of them
}