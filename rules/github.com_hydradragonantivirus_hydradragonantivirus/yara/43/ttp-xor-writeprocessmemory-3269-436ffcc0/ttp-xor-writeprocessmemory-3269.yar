rule TTP_XOR_WriteProcessMemory_3269 {
  strings:
    $key_3269 = { 65 1b [2] 57 39 [2] 51 0c [2] 7f 0c [2] 40 10 }

  condition:
    any of them
}