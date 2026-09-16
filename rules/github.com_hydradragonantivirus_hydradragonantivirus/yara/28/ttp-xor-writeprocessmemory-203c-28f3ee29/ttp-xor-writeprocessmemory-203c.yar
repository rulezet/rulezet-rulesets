rule TTP_XOR_WriteProcessMemory_203c {
  strings:
    $key_203c = { 77 4e [2] 45 6c [2] 43 59 [2] 6d 59 [2] 52 45 }

  condition:
    any of them
}