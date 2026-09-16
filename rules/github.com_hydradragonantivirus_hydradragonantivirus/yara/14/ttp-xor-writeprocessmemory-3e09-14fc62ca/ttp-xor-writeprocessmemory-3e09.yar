rule TTP_XOR_WriteProcessMemory_3e09 {
  strings:
    $key_3e09 = { 69 7b [2] 5b 59 [2] 5d 6c [2] 73 6c [2] 4c 70 }

  condition:
    any of them
}