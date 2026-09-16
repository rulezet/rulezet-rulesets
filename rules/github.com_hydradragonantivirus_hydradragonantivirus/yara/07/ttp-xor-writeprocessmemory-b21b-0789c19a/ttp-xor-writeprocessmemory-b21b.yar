rule TTP_XOR_WriteProcessMemory_b21b {
  strings:
    $key_b21b = { e5 69 [2] d7 4b [2] d1 7e [2] ff 7e [2] c0 62 }

  condition:
    any of them
}