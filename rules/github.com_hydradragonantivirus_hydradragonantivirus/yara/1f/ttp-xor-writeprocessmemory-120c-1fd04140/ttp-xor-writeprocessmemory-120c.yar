rule TTP_XOR_WriteProcessMemory_120c {
  strings:
    $key_120c = { 45 7e [2] 77 5c [2] 71 69 [2] 5f 69 [2] 60 75 }

  condition:
    any of them
}