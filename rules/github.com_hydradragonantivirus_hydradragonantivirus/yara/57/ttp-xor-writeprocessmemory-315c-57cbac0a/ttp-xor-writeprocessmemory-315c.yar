rule TTP_XOR_WriteProcessMemory_315c {
  strings:
    $key_315c = { 66 2e [2] 54 0c [2] 52 39 [2] 7c 39 [2] 43 25 }

  condition:
    any of them
}