rule TTP_XOR_WriteProcessMemory_244c {
  strings:
    $key_244c = { 73 3e [2] 41 1c [2] 47 29 [2] 69 29 [2] 56 35 }

  condition:
    any of them
}