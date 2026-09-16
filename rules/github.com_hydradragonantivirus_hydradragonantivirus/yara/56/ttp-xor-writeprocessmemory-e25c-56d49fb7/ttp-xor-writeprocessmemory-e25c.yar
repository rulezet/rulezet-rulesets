rule TTP_XOR_WriteProcessMemory_e25c {
  strings:
    $key_e25c = { b5 2e [2] 87 0c [2] 81 39 [2] af 39 [2] 90 25 }

  condition:
    any of them
}