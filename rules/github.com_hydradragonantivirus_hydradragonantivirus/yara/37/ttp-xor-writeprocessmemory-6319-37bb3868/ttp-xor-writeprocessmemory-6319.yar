rule TTP_XOR_WriteProcessMemory_6319 {
  strings:
    $key_6319 = { 34 6b [2] 06 49 [2] 00 7c [2] 2e 7c [2] 11 60 }

  condition:
    any of them
}