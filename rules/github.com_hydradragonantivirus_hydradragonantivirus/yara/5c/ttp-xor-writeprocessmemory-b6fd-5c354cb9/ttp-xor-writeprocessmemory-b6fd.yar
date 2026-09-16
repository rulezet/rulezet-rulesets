rule TTP_XOR_WriteProcessMemory_b6fd {
  strings:
    $key_b6fd = { e1 8f [2] d3 ad [2] d5 98 [2] fb 98 [2] c4 84 }

  condition:
    any of them
}