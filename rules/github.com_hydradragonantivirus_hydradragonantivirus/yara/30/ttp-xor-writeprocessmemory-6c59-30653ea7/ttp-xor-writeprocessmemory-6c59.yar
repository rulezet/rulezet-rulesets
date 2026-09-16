rule TTP_XOR_WriteProcessMemory_6c59 {
  strings:
    $key_6c59 = { 3b 2b [2] 09 09 [2] 0f 3c [2] 21 3c [2] 1e 20 }

  condition:
    any of them
}