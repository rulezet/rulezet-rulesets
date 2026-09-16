rule TTP_XOR_WriteProcessMemory_dada {
  strings:
    $key_dada = { 8d a8 [2] bf 8a [2] b9 bf [2] 97 bf [2] a8 a3 }

  condition:
    any of them
}