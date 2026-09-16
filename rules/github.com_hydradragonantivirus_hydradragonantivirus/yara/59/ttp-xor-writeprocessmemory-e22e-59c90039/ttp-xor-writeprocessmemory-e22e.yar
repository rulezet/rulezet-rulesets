rule TTP_XOR_WriteProcessMemory_e22e {
  strings:
    $key_e22e = { b5 5c [2] 87 7e [2] 81 4b [2] af 4b [2] 90 57 }

  condition:
    any of them
}