rule TTP_XOR_WriteProcessMemory_b41a {
  strings:
    $key_b41a = { e3 68 [2] d1 4a [2] d7 7f [2] f9 7f [2] c6 63 }

  condition:
    any of them
}