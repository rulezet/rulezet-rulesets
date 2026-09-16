rule TTP_XOR_WriteProcessMemory_a42e {
  strings:
    $key_a42e = { f3 5c [2] c1 7e [2] c7 4b [2] e9 4b [2] d6 57 }

  condition:
    any of them
}