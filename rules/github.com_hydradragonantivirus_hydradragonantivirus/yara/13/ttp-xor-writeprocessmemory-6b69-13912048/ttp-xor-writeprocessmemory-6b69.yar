rule TTP_XOR_WriteProcessMemory_6b69 {
  strings:
    $key_6b69 = { 3c 1b [2] 0e 39 [2] 08 0c [2] 26 0c [2] 19 10 }

  condition:
    any of them
}