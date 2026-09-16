rule TTP_XOR_WriteProcessMemory_510d {
  strings:
    $key_510d = { 06 7f [2] 34 5d [2] 32 68 [2] 1c 68 [2] 23 74 }

  condition:
    any of them
}