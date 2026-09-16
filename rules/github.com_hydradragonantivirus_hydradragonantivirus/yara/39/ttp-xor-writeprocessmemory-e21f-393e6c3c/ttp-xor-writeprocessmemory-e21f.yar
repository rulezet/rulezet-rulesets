rule TTP_XOR_WriteProcessMemory_e21f {
  strings:
    $key_e21f = { b5 6d [2] 87 4f [2] 81 7a [2] af 7a [2] 90 66 }

  condition:
    any of them
}