rule TTP_XOR_WriteProcessMemory_e24c {
  strings:
    $key_e24c = { b5 3e [2] 87 1c [2] 81 29 [2] af 29 [2] 90 35 }

  condition:
    any of them
}