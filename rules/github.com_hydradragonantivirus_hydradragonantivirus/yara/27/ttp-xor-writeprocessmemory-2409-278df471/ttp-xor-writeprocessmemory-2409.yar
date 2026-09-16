rule TTP_XOR_WriteProcessMemory_2409 {
  strings:
    $key_2409 = { 73 7b [2] 41 59 [2] 47 6c [2] 69 6c [2] 56 70 }

  condition:
    any of them
}