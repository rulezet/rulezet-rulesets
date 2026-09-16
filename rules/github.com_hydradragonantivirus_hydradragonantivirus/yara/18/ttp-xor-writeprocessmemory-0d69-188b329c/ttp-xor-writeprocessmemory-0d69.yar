rule TTP_XOR_WriteProcessMemory_0d69 {
  strings:
    $key_0d69 = { 5a 1b [2] 68 39 [2] 6e 0c [2] 40 0c [2] 7f 10 }

  condition:
    any of them
}