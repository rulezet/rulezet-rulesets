rule TTP_XOR_WriteProcessMemory_c96a {
  strings:
    $key_c96a = { 9e 18 [2] ac 3a [2] aa 0f [2] 84 0f [2] bb 13 }

  condition:
    any of them
}