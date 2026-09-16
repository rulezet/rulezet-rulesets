rule TTP_XOR_WriteProcessMemory_e21e {
  strings:
    $key_e21e = { b5 6c [2] 87 4e [2] 81 7b [2] af 7b [2] 90 67 }

  condition:
    any of them
}