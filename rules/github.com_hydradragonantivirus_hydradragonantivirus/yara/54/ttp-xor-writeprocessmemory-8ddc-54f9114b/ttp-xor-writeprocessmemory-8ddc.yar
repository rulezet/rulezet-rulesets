rule TTP_XOR_WriteProcessMemory_8ddc {
  strings:
    $key_8ddc = { da ae [2] e8 8c [2] ee b9 [2] c0 b9 [2] ff a5 }

  condition:
    any of them
}