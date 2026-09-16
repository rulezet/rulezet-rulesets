rule TTP_XOR_WriteProcessMemory_3c95 {
  strings:
    $key_3c95 = { 6b e7 [2] 59 c5 [2] 5f f0 [2] 71 f0 [2] 4e ec }

  condition:
    any of them
}