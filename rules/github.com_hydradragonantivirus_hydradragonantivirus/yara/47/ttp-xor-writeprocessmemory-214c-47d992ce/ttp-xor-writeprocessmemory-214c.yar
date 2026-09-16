rule TTP_XOR_WriteProcessMemory_214c {
  strings:
    $key_214c = { 76 3e [2] 44 1c [2] 42 29 [2] 6c 29 [2] 53 35 }

  condition:
    any of them
}