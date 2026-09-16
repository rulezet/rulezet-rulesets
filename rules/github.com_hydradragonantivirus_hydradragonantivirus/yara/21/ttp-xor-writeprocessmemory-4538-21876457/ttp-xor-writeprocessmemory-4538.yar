rule TTP_XOR_WriteProcessMemory_4538 {
  strings:
    $key_4538 = { 12 4a [2] 20 68 [2] 26 5d [2] 08 5d [2] 37 41 }

  condition:
    any of them
}