rule TTP_XOR_WriteProcessMemory_7159 {
  strings:
    $key_7159 = { 26 2b [2] 14 09 [2] 12 3c [2] 3c 3c [2] 03 20 }

  condition:
    any of them
}