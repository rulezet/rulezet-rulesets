rule TTP_XOR_WriteProcessMemory_272c {
  strings:
    $key_272c = { 70 5e [2] 42 7c [2] 44 49 [2] 6a 49 [2] 55 55 }

  condition:
    any of them
}