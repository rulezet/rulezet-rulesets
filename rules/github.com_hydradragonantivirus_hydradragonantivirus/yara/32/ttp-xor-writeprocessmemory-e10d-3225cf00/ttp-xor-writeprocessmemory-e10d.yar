rule TTP_XOR_WriteProcessMemory_e10d {
  strings:
    $key_e10d = { b6 7f [2] 84 5d [2] 82 68 [2] ac 68 [2] 93 74 }

  condition:
    any of them
}