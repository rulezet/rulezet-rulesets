rule TTP_XOR_WriteProcessMemory_e14a {
  strings:
    $key_e14a = { b6 38 [2] 84 1a [2] 82 2f [2] ac 2f [2] 93 33 }

  condition:
    any of them
}