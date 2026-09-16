rule TTP_XOR_WriteProcessMemory_e2f8 {
  strings:
    $key_e2f8 = { b5 8a [2] 87 a8 [2] 81 9d [2] af 9d [2] 90 81 }

  condition:
    any of them
}