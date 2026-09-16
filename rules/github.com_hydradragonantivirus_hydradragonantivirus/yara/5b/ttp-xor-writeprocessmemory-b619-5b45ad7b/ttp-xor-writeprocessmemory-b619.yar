rule TTP_XOR_WriteProcessMemory_b619 {
  strings:
    $key_b619 = { e1 6b [2] d3 49 [2] d5 7c [2] fb 7c [2] c4 60 }

  condition:
    any of them
}