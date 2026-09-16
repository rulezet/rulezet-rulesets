rule TTP_XOR_WriteProcessMemory_ef79 {
  strings:
    $key_ef79 = { b8 0b [2] 8a 29 [2] 8c 1c [2] a2 1c [2] 9d 00 }

  condition:
    any of them
}