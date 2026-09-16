rule TTP_XOR_WriteProcessMemory_3891 {
  strings:
    $key_3891 = { 6f e3 [2] 5d c1 [2] 5b f4 [2] 75 f4 [2] 4a e8 }

  condition:
    any of them
}