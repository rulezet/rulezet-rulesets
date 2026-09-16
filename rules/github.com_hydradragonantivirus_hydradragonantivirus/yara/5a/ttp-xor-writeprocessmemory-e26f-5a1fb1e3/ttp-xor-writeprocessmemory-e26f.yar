rule TTP_XOR_WriteProcessMemory_e26f {
  strings:
    $key_e26f = { b5 1d [2] 87 3f [2] 81 0a [2] af 0a [2] 90 16 }

  condition:
    any of them
}