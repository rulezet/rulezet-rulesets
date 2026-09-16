rule TTP_XOR_WriteProcessMemory_a6bf {
  strings:
    $key_a6bf = { f1 cd [2] c3 ef [2] c5 da [2] eb da [2] d4 c6 }

  condition:
    any of them
}