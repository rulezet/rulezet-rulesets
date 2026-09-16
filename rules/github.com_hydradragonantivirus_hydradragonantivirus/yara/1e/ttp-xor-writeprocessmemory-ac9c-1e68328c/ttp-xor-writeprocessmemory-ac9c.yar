rule TTP_XOR_WriteProcessMemory_ac9c {
  strings:
    $key_ac9c = { fb ee [2] c9 cc [2] cf f9 [2] e1 f9 [2] de e5 }

  condition:
    any of them
}