rule TTP_XOR_WriteProcessMemory_ef69 {
  strings:
    $key_ef69 = { b8 1b [2] 8a 39 [2] 8c 0c [2] a2 0c [2] 9d 10 }

  condition:
    any of them
}