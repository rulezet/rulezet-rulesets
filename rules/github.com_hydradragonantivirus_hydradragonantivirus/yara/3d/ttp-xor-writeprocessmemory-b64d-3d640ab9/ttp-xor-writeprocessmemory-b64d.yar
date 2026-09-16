rule TTP_XOR_WriteProcessMemory_b64d {
  strings:
    $key_b64d = { e1 3f [2] d3 1d [2] d5 28 [2] fb 28 [2] c4 34 }

  condition:
    any of them
}