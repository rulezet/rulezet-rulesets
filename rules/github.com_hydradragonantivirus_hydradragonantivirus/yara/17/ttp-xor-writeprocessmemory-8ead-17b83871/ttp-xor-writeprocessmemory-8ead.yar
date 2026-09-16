rule TTP_XOR_WriteProcessMemory_8ead {
  strings:
    $key_8ead = { d9 df [2] eb fd [2] ed c8 [2] c3 c8 [2] fc d4 }

  condition:
    any of them
}