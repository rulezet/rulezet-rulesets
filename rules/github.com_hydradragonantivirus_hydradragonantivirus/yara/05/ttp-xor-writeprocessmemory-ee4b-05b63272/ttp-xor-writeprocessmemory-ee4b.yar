rule TTP_XOR_WriteProcessMemory_ee4b {
  strings:
    $key_ee4b = { b9 39 [2] 8b 1b [2] 8d 2e [2] a3 2e [2] 9c 32 }

  condition:
    any of them
}