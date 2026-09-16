rule TTP_XOR_WriteProcessMemory_2868 {
  strings:
    $key_2868 = { 7f 1a [2] 4d 38 [2] 4b 0d [2] 65 0d [2] 5a 11 }

  condition:
    any of them
}