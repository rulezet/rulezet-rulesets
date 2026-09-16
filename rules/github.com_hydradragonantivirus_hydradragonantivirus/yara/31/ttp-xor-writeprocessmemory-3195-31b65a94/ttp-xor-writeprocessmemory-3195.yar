rule TTP_XOR_WriteProcessMemory_3195 {
  strings:
    $key_3195 = { 66 e7 [2] 54 c5 [2] 52 f0 [2] 7c f0 [2] 43 ec }

  condition:
    any of them
}