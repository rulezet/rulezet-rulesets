rule TTP_XOR_WriteProcessMemory_b0fd {
  strings:
    $key_b0fd = { e7 8f [2] d5 ad [2] d3 98 [2] fd 98 [2] c2 84 }

  condition:
    any of them
}