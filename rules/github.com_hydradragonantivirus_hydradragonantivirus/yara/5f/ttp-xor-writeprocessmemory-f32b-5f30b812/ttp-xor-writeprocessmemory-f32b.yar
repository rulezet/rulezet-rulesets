rule TTP_XOR_WriteProcessMemory_f32b {
  strings:
    $key_f32b = { a4 59 [2] 96 7b [2] 90 4e [2] be 4e [2] 81 52 }

  condition:
    any of them
}