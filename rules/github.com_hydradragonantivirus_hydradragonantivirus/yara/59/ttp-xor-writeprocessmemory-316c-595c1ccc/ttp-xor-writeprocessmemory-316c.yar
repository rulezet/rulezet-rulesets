rule TTP_XOR_WriteProcessMemory_316c {
  strings:
    $key_316c = { 66 1e [2] 54 3c [2] 52 09 [2] 7c 09 [2] 43 15 }

  condition:
    any of them
}