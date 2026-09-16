rule TTP_XOR_WriteProcessMemory_ef1c {
  strings:
    $key_ef1c = { b8 6e [2] 8a 4c [2] 8c 79 [2] a2 79 [2] 9d 65 }

  condition:
    any of them
}