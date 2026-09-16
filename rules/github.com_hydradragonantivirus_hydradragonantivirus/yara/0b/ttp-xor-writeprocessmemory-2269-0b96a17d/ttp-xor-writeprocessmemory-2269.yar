rule TTP_XOR_WriteProcessMemory_2269 {
  strings:
    $key_2269 = { 75 1b [2] 47 39 [2] 41 0c [2] 6f 0c [2] 50 10 }

  condition:
    any of them
}