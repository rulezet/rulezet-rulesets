rule TTP_XOR_WriteProcessMemory_b20d {
  strings:
    $key_b20d = { e5 7f [2] d7 5d [2] d1 68 [2] ff 68 [2] c0 74 }

  condition:
    any of them
}