rule TTP_XOR_WriteProcessMemory_8d97 {
  strings:
    $key_8d97 = { da e5 [2] e8 c7 [2] ee f2 [2] c0 f2 [2] ff ee }

  condition:
    any of them
}