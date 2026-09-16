rule TTP_XOR_WriteProcessMemory_b087 {
  strings:
    $key_b087 = { e7 f5 [2] d5 d7 [2] d3 e2 [2] fd e2 [2] c2 fe }

  condition:
    any of them
}