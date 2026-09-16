rule TTP_XOR_WriteProcessMemory_1230 {
  strings:
    $key_1230 = { 45 42 [2] 77 60 [2] 71 55 [2] 5f 55 [2] 60 49 }

  condition:
    any of them
}