rule TTP_XOR_WriteProcessMemory_d8d3 {
  strings:
    $key_d8d3 = { 8f a1 [2] bd 83 [2] bb b6 [2] 95 b6 [2] aa aa }

  condition:
    any of them
}