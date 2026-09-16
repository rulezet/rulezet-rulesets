rule TTP_XOR_WriteProcessMemory_4c09 {
  strings:
    $key_4c09 = { 1b 7b [2] 29 59 [2] 2f 6c [2] 01 6c [2] 3e 70 }

  condition:
    any of them
}