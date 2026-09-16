rule TTP_XOR_WriteProcessMemory_e252 {
  strings:
    $key_e252 = { b5 20 [2] 87 02 [2] 81 37 [2] af 37 [2] 90 2b }

  condition:
    any of them
}