rule TTP_XOR_WriteProcessMemory_2ba9 {
  strings:
    $key_2ba9 = { 7c db [2] 4e f9 [2] 48 cc [2] 66 cc [2] 59 d0 }

  condition:
    any of them
}