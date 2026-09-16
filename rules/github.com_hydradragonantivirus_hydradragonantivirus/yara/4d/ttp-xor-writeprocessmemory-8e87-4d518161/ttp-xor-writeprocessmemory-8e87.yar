rule TTP_XOR_WriteProcessMemory_8e87 {
  strings:
    $key_8e87 = { d9 f5 [2] eb d7 [2] ed e2 [2] c3 e2 [2] fc fe }

  condition:
    any of them
}