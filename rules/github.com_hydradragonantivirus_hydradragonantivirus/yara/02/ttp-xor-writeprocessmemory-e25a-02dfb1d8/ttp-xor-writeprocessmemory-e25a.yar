rule TTP_XOR_WriteProcessMemory_e25a {
  strings:
    $key_e25a = { b5 28 [2] 87 0a [2] 81 3f [2] af 3f [2] 90 23 }

  condition:
    any of them
}