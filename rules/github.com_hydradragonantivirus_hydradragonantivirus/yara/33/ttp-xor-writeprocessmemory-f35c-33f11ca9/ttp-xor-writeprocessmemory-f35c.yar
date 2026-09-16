rule TTP_XOR_WriteProcessMemory_f35c {
  strings:
    $key_f35c = { a4 2e [2] 96 0c [2] 90 39 [2] be 39 [2] 81 25 }

  condition:
    any of them
}