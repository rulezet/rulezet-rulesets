rule TTP_XOR_WriteProcessMemory_095c {
  strings:
    $key_095c = { 5e 2e [2] 6c 0c [2] 6a 39 [2] 44 39 [2] 7b 25 }

  condition:
    any of them
}