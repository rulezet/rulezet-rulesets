rule TTP_XOR_WriteProcessMemory_e55c {
  strings:
    $key_e55c = { b2 2e [2] 80 0c [2] 86 39 [2] a8 39 [2] 97 25 }

  condition:
    any of them
}