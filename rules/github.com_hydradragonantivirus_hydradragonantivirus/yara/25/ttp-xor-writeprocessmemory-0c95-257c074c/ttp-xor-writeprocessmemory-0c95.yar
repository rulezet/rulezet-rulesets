rule TTP_XOR_WriteProcessMemory_0c95 {
  strings:
    $key_0c95 = { 5b e7 [2] 69 c5 [2] 6f f0 [2] 41 f0 [2] 7e ec }

  condition:
    any of them
}