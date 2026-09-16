rule TTP_XOR_WriteProcessMemory_5c59 {
  strings:
    $key_5c59 = { 0b 2b [2] 39 09 [2] 3f 3c [2] 11 3c [2] 2e 20 }

  condition:
    any of them
}