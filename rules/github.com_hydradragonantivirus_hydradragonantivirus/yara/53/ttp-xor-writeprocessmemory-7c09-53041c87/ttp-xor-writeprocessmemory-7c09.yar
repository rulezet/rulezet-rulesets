rule TTP_XOR_WriteProcessMemory_7c09 {
  strings:
    $key_7c09 = { 2b 7b [2] 19 59 [2] 1f 6c [2] 31 6c [2] 0e 70 }

  condition:
    any of them
}