rule TTP_XOR_WriteProcessMemory_0a3e {
  strings:
    $key_0a3e = { 5d 4c [2] 6f 6e [2] 69 5b [2] 47 5b [2] 78 47 }

  condition:
    any of them
}