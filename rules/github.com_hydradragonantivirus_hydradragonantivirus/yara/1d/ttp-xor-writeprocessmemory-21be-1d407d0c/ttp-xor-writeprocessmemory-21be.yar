rule TTP_XOR_WriteProcessMemory_21be {
  strings:
    $key_21be = { 76 cc [2] 44 ee [2] 42 db [2] 6c db [2] 53 c7 }

  condition:
    any of them
}