rule TTP_XOR_WriteProcessMemory_eb6e {
  strings:
    $key_eb6e = { bc 1c [2] 8e 3e [2] 88 0b [2] a6 0b [2] 99 17 }

  condition:
    any of them
}