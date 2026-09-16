rule TTP_XOR_WriteProcessMemory_b01a {
  strings:
    $key_b01a = { e7 68 [2] d5 4a [2] d3 7f [2] fd 7f [2] c2 63 }

  condition:
    any of them
}