rule TTP_XOR_WriteProcessMemory_3459 {
  strings:
    $key_3459 = { 63 2b [2] 51 09 [2] 57 3c [2] 79 3c [2] 46 20 }

  condition:
    any of them
}