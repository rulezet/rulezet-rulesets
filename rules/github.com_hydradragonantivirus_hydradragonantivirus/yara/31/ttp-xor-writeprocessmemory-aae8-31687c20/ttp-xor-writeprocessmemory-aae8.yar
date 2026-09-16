rule TTP_XOR_WriteProcessMemory_aae8 {
  strings:
    $key_aae8 = { fd 9a [2] cf b8 [2] c9 8d [2] e7 8d [2] d8 91 }

  condition:
    any of them
}