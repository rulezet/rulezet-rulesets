rule TTP_XOR_WriteProcessMemory_e14d {
  strings:
    $key_e14d = { b6 3f [2] 84 1d [2] 82 28 [2] ac 28 [2] 93 34 }

  condition:
    any of them
}