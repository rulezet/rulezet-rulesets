rule TTP_XOR_WriteProcessMemory_3b59 {
  strings:
    $key_3b59 = { 6c 2b [2] 5e 09 [2] 58 3c [2] 76 3c [2] 49 20 }

  condition:
    any of them
}