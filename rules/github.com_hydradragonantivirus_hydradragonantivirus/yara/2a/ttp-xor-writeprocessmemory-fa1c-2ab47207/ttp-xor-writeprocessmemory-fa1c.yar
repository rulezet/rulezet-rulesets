rule TTP_XOR_WriteProcessMemory_fa1c {
  strings:
    $key_fa1c = { ad 6e [2] 9f 4c [2] 99 79 [2] b7 79 [2] 88 65 }

  condition:
    any of them
}