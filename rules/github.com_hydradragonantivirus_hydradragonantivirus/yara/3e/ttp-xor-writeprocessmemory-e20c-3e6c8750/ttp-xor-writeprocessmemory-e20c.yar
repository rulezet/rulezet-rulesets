rule TTP_XOR_WriteProcessMemory_e20c {
  strings:
    $key_e20c = { b5 7e [2] 87 5c [2] 81 69 [2] af 69 [2] 90 75 }

  condition:
    any of them
}