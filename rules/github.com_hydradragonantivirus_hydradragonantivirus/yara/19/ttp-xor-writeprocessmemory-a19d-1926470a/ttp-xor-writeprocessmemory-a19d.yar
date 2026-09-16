rule TTP_XOR_WriteProcessMemory_a19d {
  strings:
    $key_a19d = { f6 ef [2] c4 cd [2] c2 f8 [2] ec f8 [2] d3 e4 }

  condition:
    any of them
}