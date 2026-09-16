rule TTP_XOR_WriteProcessMemory_102e {
  strings:
    $key_102e = { 47 5c [2] 75 7e [2] 73 4b [2] 5d 4b [2] 62 57 }

  condition:
    any of them
}