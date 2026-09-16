rule TTP_XOR_WriteProcessMemory_665c {
  strings:
    $key_665c = { 31 2e [2] 03 0c [2] 05 39 [2] 2b 39 [2] 14 25 }

  condition:
    any of them
}