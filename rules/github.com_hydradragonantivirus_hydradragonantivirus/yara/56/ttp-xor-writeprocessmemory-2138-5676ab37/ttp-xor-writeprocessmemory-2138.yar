rule TTP_XOR_WriteProcessMemory_2138 {
  strings:
    $key_2138 = { 76 4a [2] 44 68 [2] 42 5d [2] 6c 5d [2] 53 41 }

  condition:
    any of them
}