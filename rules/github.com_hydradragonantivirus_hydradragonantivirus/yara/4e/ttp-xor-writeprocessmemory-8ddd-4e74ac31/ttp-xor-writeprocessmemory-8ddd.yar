rule TTP_XOR_WriteProcessMemory_8ddd {
  strings:
    $key_8ddd = { da af [2] e8 8d [2] ee b8 [2] c0 b8 [2] ff a4 }

  condition:
    any of them
}