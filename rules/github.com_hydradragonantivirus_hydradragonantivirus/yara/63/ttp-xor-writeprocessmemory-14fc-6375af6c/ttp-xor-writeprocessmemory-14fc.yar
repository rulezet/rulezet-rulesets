rule TTP_XOR_WriteProcessMemory_14fc {
  strings:
    $key_14fc = { 43 8e [2] 71 ac [2] 77 99 [2] 59 99 [2] 66 85 }

  condition:
    any of them
}