rule TTP_XOR_WriteProcessMemory_e27f {
  strings:
    $key_e27f = { b5 0d [2] 87 2f [2] 81 1a [2] af 1a [2] 90 06 }

  condition:
    any of them
}