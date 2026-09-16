rule TTP_XOR_WriteProcessMemory_6209 {
  strings:
    $key_6209 = { 35 7b [2] 07 59 [2] 01 6c [2] 2f 6c [2] 10 70 }

  condition:
    any of them
}