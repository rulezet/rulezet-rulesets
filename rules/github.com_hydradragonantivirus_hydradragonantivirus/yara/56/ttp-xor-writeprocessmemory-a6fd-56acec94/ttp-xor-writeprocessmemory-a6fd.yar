rule TTP_XOR_WriteProcessMemory_a6fd {
  strings:
    $key_a6fd = { f1 8f [2] c3 ad [2] c5 98 [2] eb 98 [2] d4 84 }

  condition:
    any of them
}