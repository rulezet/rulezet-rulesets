rule TTP_XOR_WriteProcessMemory_b64f {
  strings:
    $key_b64f = { e1 3d [2] d3 1f [2] d5 2a [2] fb 2a [2] c4 36 }

  condition:
    any of them
}