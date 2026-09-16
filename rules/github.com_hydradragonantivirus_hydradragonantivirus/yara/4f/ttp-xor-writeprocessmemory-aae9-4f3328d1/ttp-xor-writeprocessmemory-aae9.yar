rule TTP_XOR_WriteProcessMemory_aae9 {
  strings:
    $key_aae9 = { fd 9b [2] cf b9 [2] c9 8c [2] e7 8c [2] d8 90 }

  condition:
    any of them
}