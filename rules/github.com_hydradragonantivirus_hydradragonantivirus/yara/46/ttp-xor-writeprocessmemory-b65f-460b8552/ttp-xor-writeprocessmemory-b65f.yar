rule TTP_XOR_WriteProcessMemory_b65f {
  strings:
    $key_b65f = { e1 2d [2] d3 0f [2] d5 3a [2] fb 3a [2] c4 26 }

  condition:
    any of them
}