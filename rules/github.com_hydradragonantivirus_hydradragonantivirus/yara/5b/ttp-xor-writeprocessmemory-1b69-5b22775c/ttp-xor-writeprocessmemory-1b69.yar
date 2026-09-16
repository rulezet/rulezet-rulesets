rule TTP_XOR_WriteProcessMemory_1b69 {
  strings:
    $key_1b69 = { 4c 1b [2] 7e 39 [2] 78 0c [2] 56 0c [2] 69 10 }

  condition:
    any of them
}