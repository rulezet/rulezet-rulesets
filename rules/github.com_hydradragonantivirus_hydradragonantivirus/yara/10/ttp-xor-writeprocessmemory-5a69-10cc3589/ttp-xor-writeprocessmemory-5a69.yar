rule TTP_XOR_WriteProcessMemory_5a69 {
  strings:
    $key_5a69 = { 0d 1b [2] 3f 39 [2] 39 0c [2] 17 0c [2] 28 10 }

  condition:
    any of them
}