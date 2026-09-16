rule TTP_XOR_WriteProcessMemory_7a30 {
  strings:
    $key_7a30 = { 2d 42 [2] 1f 60 [2] 19 55 [2] 37 55 [2] 08 49 }

  condition:
    any of them
}