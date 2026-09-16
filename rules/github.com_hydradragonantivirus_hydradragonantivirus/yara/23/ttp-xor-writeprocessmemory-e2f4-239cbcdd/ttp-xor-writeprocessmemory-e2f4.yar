rule TTP_XOR_WriteProcessMemory_e2f4 {
  strings:
    $key_e2f4 = { b5 86 [2] 87 a4 [2] 81 91 [2] af 91 [2] 90 8d }

  condition:
    any of them
}