rule TTP_XOR_WriteProcessMemory_e23d {
  strings:
    $key_e23d = { b5 4f [2] 87 6d [2] 81 58 [2] af 58 [2] 90 44 }

  condition:
    any of them
}