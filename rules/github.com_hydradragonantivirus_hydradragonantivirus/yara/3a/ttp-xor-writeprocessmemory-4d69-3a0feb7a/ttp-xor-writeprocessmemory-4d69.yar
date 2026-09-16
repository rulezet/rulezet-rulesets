rule TTP_XOR_WriteProcessMemory_4d69 {
  strings:
    $key_4d69 = { 1a 1b [2] 28 39 [2] 2e 0c [2] 00 0c [2] 3f 10 }

  condition:
    any of them
}