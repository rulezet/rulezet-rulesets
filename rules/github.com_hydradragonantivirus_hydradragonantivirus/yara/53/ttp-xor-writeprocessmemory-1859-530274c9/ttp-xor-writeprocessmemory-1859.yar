rule TTP_XOR_WriteProcessMemory_1859 {
  strings:
    $key_1859 = { 4f 2b [2] 7d 09 [2] 7b 3c [2] 55 3c [2] 6a 20 }

  condition:
    any of them
}