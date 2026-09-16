rule TTP_XOR_WriteProcessMemory_e13a {
  strings:
    $key_e13a = { b6 48 [2] 84 6a [2] 82 5f [2] ac 5f [2] 93 43 }

  condition:
    any of them
}