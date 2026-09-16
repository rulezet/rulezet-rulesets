rule TTP_XOR_WriteProcessMemory_a1c6 {
  strings:
    $key_a1c6 = { f6 b4 [2] c4 96 [2] c2 a3 [2] ec a3 [2] d3 bf }

  condition:
    any of them
}