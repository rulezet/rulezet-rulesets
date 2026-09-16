rule TTP_XOR_WriteProcessMemory_e217 {
  strings:
    $key_e217 = { b5 65 [2] 87 47 [2] 81 72 [2] af 72 [2] 90 6e }

  condition:
    any of them
}