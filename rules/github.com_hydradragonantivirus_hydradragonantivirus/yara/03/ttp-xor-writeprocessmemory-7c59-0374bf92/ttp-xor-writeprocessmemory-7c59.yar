rule TTP_XOR_WriteProcessMemory_7c59 {
  strings:
    $key_7c59 = { 2b 2b [2] 19 09 [2] 1f 3c [2] 31 3c [2] 0e 20 }

  condition:
    any of them
}