rule TTP_XOR_WriteProcessMemory_aae4 {
  strings:
    $key_aae4 = { fd 96 [2] cf b4 [2] c9 81 [2] e7 81 [2] d8 9d }

  condition:
    any of them
}