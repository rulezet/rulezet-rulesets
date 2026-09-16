rule TTP_XOR_WriteProcessMemory_eb1c {
  strings:
    $key_eb1c = { bc 6e [2] 8e 4c [2] 88 79 [2] a6 79 [2] 99 65 }

  condition:
    any of them
}