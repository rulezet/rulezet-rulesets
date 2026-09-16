rule TTP_XOR_WriteProcessMemory_526c {
  strings:
    $key_526c = { 05 1e [2] 37 3c [2] 31 09 [2] 1f 09 [2] 20 15 }

  condition:
    any of them
}