rule TTP_XOR_WriteProcessMemory_b299 {
  strings:
    $key_b299 = { e5 eb [2] d7 c9 [2] d1 fc [2] ff fc [2] c0 e0 }

  condition:
    any of them
}