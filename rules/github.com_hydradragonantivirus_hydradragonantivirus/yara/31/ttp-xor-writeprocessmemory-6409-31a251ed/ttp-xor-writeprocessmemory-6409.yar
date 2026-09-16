rule TTP_XOR_WriteProcessMemory_6409 {
  strings:
    $key_6409 = { 33 7b [2] 01 59 [2] 07 6c [2] 29 6c [2] 16 70 }

  condition:
    any of them
}