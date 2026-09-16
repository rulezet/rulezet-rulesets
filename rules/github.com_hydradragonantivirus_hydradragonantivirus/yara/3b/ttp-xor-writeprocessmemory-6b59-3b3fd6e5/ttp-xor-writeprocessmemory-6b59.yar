rule TTP_XOR_WriteProcessMemory_6b59 {
  strings:
    $key_6b59 = { 3c 2b [2] 0e 09 [2] 08 3c [2] 26 3c [2] 19 20 }

  condition:
    any of them
}