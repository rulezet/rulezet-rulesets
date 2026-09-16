rule TTP_XOR_WriteProcessMemory_e16a {
  strings:
    $key_e16a = { b6 18 [2] 84 3a [2] 82 0f [2] ac 0f [2] 93 13 }

  condition:
    any of them
}