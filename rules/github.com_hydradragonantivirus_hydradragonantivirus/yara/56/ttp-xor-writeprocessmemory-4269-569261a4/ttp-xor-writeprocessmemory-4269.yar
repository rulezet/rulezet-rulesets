rule TTP_XOR_WriteProcessMemory_4269 {
  strings:
    $key_4269 = { 15 1b [2] 27 39 [2] 21 0c [2] 0f 0c [2] 30 10 }

  condition:
    any of them
}