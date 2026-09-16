rule TTP_XOR_WriteProcessMemory_2159 {
  strings:
    $key_2159 = { 76 2b [2] 44 09 [2] 42 3c [2] 6c 3c [2] 53 20 }

  condition:
    any of them
}