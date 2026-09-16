rule TTP_XOR_WriteProcessMemory_ef29 {
  strings:
    $key_ef29 = { b8 5b [2] 8a 79 [2] 8c 4c [2] a2 4c [2] 9d 50 }

  condition:
    any of them
}