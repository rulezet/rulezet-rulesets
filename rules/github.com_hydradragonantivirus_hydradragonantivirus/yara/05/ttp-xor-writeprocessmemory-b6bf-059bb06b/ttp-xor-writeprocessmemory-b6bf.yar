rule TTP_XOR_WriteProcessMemory_b6bf {
  strings:
    $key_b6bf = { e1 cd [2] d3 ef [2] d5 da [2] fb da [2] c4 c6 }

  condition:
    any of them
}