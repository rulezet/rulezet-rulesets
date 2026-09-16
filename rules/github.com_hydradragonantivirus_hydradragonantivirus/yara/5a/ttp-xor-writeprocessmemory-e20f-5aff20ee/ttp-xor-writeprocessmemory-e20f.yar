rule TTP_XOR_WriteProcessMemory_e20f {
  strings:
    $key_e20f = { b5 7d [2] 87 5f [2] 81 6a [2] af 6a [2] 90 76 }

  condition:
    any of them
}