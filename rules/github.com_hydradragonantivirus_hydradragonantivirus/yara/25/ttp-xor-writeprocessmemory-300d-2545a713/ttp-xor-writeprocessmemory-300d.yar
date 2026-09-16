rule TTP_XOR_WriteProcessMemory_300d {
  strings:
    $key_300d = { 67 7f [2] 55 5d [2] 53 68 [2] 7d 68 [2] 42 74 }

  condition:
    any of them
}