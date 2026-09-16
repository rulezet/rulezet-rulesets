rule TTP_XOR_WriteProcessMemory_79de {
  strings:
    $key_79de = { 2e ac [2] 1c 8e [2] 1a bb [2] 34 bb [2] 0b a7 }

  condition:
    any of them
}