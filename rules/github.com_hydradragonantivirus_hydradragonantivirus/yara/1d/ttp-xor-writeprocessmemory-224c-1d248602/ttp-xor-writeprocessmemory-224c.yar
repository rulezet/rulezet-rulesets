rule TTP_XOR_WriteProcessMemory_224c {
  strings:
    $key_224c = { 75 3e [2] 47 1c [2] 41 29 [2] 6f 29 [2] 50 35 }

  condition:
    any of them
}