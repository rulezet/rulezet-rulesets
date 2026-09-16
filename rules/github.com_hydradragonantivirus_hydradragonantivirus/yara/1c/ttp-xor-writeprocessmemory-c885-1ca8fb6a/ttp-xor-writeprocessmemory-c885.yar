rule TTP_XOR_WriteProcessMemory_c885 {
  strings:
    $key_c885 = { 9f f7 [2] ad d5 [2] ab e0 [2] 85 e0 [2] ba fc }

  condition:
    any of them
}