rule TTP_XOR_WriteProcessMemory_e22b {
  strings:
    $key_e22b = { b5 59 [2] 87 7b [2] 81 4e [2] af 4e [2] 90 52 }

  condition:
    any of them
}