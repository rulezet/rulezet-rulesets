rule TTP_XOR_WriteProcessMemory_b68d {
  strings:
    $key_b68d = { e1 ff [2] d3 dd [2] d5 e8 [2] fb e8 [2] c4 f4 }

  condition:
    any of them
}