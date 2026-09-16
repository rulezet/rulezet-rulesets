rule TTP_XOR_WriteProcessMemory_e26c {
  strings:
    $key_e26c = { b5 1e [2] 87 3c [2] 81 09 [2] af 09 [2] 90 15 }

  condition:
    any of them
}