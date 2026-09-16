rule TTP_XOR_WriteProcessMemory_5205 {
  strings:
    $key_5205 = { 05 77 [2] 37 55 [2] 31 60 [2] 1f 60 [2] 20 7c }

  condition:
    any of them
}