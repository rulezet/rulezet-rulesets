rule TTP_XOR_WriteProcessMemory_e248 {
  strings:
    $key_e248 = { b5 3a [2] 87 18 [2] 81 2d [2] af 2d [2] 90 31 }

  condition:
    any of them
}