rule TTP_XOR_WriteProcessMemory_7538 {
  strings:
    $key_7538 = { 22 4a [2] 10 68 [2] 16 5d [2] 38 5d [2] 07 41 }

  condition:
    any of them
}