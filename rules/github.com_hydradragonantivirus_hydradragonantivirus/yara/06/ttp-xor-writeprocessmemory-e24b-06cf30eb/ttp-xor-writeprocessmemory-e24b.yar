rule TTP_XOR_WriteProcessMemory_e24b {
  strings:
    $key_e24b = { b5 39 [2] 87 1b [2] 81 2e [2] af 2e [2] 90 32 }

  condition:
    any of them
}