rule TTP_XOR_WriteProcessMemory_b64a {
  strings:
    $key_b64a = { e1 38 [2] d3 1a [2] d5 2f [2] fb 2f [2] c4 33 }

  condition:
    any of them
}