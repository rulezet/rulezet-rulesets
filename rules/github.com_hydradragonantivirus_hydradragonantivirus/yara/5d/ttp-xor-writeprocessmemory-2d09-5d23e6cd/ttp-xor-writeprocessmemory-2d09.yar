rule TTP_XOR_WriteProcessMemory_2d09 {
  strings:
    $key_2d09 = { 7a 7b [2] 48 59 [2] 4e 6c [2] 60 6c [2] 5f 70 }

  condition:
    any of them
}