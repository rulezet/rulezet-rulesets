rule TTP_XOR_WriteProcessMemory_a2de {
  strings:
    $key_a2de = { f5 ac [2] c7 8e [2] c1 bb [2] ef bb [2] d0 a7 }

  condition:
    any of them
}