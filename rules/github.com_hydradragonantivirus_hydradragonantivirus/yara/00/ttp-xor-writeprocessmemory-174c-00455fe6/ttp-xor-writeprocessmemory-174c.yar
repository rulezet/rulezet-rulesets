rule TTP_XOR_WriteProcessMemory_174c {
  strings:
    $key_174c = { 40 3e [2] 72 1c [2] 74 29 [2] 5a 29 [2] 65 35 }

  condition:
    any of them
}