rule TTP_XOR_WriteProcessMemory_e268 {
  strings:
    $key_e268 = { b5 1a [2] 87 38 [2] 81 0d [2] af 0d [2] 90 11 }

  condition:
    any of them
}