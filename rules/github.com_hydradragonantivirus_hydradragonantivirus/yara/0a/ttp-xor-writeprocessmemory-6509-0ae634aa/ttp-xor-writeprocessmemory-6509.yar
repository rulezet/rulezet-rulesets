rule TTP_XOR_WriteProcessMemory_6509 {
  strings:
    $key_6509 = { 32 7b [2] 00 59 [2] 06 6c [2] 28 6c [2] 17 70 }

  condition:
    any of them
}