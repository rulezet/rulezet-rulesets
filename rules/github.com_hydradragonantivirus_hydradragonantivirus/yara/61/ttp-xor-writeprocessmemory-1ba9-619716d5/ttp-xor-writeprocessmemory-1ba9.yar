rule TTP_XOR_WriteProcessMemory_1ba9 {
  strings:
    $key_1ba9 = { 4c db [2] 7e f9 [2] 78 cc [2] 56 cc [2] 69 d0 }

  condition:
    any of them
}