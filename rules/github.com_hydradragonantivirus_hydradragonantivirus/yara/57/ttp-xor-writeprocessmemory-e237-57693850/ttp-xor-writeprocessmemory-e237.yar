rule TTP_XOR_WriteProcessMemory_e237 {
  strings:
    $key_e237 = { b5 45 [2] 87 67 [2] 81 52 [2] af 52 [2] 90 4e }

  condition:
    any of them
}