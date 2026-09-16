rule TTP_XOR_WriteProcessMemory_0a69 {
  strings:
    $key_0a69 = { 5d 1b [2] 6f 39 [2] 69 0c [2] 47 0c [2] 78 10 }

  condition:
    any of them
}