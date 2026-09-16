rule TTP_XOR_WriteProcessMemory_0d59 {
  strings:
    $key_0d59 = { 5a 2b [2] 68 09 [2] 6e 3c [2] 40 3c [2] 7f 20 }

  condition:
    any of them
}