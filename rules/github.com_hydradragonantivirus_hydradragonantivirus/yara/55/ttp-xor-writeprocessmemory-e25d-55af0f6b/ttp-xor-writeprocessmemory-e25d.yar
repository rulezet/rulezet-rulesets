rule TTP_XOR_WriteProcessMemory_e25d {
  strings:
    $key_e25d = { b5 2f [2] 87 0d [2] 81 38 [2] af 38 [2] 90 24 }

  condition:
    any of them
}