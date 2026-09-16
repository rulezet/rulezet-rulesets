rule TTP_XOR_WriteProcessMemory_c85c {
  strings:
    $key_c85c = { 9f 2e [2] ad 0c [2] ab 39 [2] 85 39 [2] ba 25 }

  condition:
    any of them
}