rule TTP_XOR_WriteProcessMemory_e24a {
  strings:
    $key_e24a = { b5 38 [2] 87 1a [2] 81 2f [2] af 2f [2] 90 33 }

  condition:
    any of them
}