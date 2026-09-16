rule TTP_XOR_WriteProcessMemory_561c {
  strings:
    $key_561c = { 01 6e [2] 33 4c [2] 35 79 [2] 1b 79 [2] 24 65 }

  condition:
    any of them
}