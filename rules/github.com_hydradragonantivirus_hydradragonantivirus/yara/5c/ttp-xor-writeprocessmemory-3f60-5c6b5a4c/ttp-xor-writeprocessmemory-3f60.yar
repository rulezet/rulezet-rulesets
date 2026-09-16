rule TTP_XOR_WriteProcessMemory_3f60 {
  strings:
    $key_3f60 = { 68 12 [2] 5a 30 [2] 5c 05 [2] 72 05 [2] 4d 19 }

  condition:
    any of them
}