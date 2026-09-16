rule TTP_XOR_WriteProcessMemory_fade {
  strings:
    $key_fade = { ad ac [2] 9f 8e [2] 99 bb [2] b7 bb [2] 88 a7 }

  condition:
    any of them
}