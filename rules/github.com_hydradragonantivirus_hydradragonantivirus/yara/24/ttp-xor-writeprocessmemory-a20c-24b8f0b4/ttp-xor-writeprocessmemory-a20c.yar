rule TTP_XOR_WriteProcessMemory_a20c {
  strings:
    $key_a20c = { f5 7e [2] c7 5c [2] c1 69 [2] ef 69 [2] d0 75 }

  condition:
    any of them
}