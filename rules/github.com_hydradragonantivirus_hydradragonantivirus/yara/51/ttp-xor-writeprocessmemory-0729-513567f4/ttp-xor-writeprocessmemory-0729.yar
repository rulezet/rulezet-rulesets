rule TTP_XOR_WriteProcessMemory_0729 {
  strings:
    $key_0729 = { 50 5b [2] 62 79 [2] 64 4c [2] 4a 4c [2] 75 50 }

  condition:
    any of them
}