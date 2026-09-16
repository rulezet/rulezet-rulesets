rule TTP_XOR_WriteProcessMemory_5a30 {
  strings:
    $key_5a30 = { 0d 42 [2] 3f 60 [2] 39 55 [2] 17 55 [2] 28 49 }

  condition:
    any of them
}