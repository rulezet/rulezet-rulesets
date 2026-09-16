rule TTP_XOR_WriteProcessMemory_315d {
  strings:
    $key_315d = { 66 2f [2] 54 0d [2] 52 38 [2] 7c 38 [2] 43 24 }

  condition:
    any of them
}