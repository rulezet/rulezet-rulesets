rule TTP_XOR_WriteProcessMemory_5409 {
  strings:
    $key_5409 = { 03 7b [2] 31 59 [2] 37 6c [2] 19 6c [2] 26 70 }

  condition:
    any of them
}