rule TTP_XOR_WriteProcessMemory_4509 {
  strings:
    $key_4509 = { 12 7b [2] 20 59 [2] 26 6c [2] 08 6c [2] 37 70 }

  condition:
    any of them
}