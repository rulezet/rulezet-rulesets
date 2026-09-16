rule TTP_XOR_WriteProcessMemory_0059 {
  strings:
    $key_0059 = { 57 2b [2] 65 09 [2] 63 3c [2] 4d 3c [2] 72 20 }

  condition:
    any of them
}