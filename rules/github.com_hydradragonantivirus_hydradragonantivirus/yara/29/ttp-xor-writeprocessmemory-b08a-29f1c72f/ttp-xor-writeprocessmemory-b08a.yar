rule TTP_XOR_WriteProcessMemory_b08a {
  strings:
    $key_b08a = { e7 f8 [2] d5 da [2] d3 ef [2] fd ef [2] c2 f3 }

  condition:
    any of them
}