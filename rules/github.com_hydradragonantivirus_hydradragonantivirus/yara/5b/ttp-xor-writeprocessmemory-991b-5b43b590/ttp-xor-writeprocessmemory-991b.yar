rule TTP_XOR_WriteProcessMemory_991b {
  strings:
    $key_991b = { ce 69 [2] fc 4b [2] fa 7e [2] d4 7e [2] eb 62 }

  condition:
    any of them
}