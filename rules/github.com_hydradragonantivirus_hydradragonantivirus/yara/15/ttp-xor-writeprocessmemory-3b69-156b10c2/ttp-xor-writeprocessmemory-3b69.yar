rule TTP_XOR_WriteProcessMemory_3b69 {
  strings:
    $key_3b69 = { 6c 1b [2] 5e 39 [2] 58 0c [2] 76 0c [2] 49 10 }

  condition:
    any of them
}