rule TTP_XOR_WriteProcessMemory_fdc4 {
  strings:
    $key_fdc4 = { aa b6 [2] 98 94 [2] 9e a1 [2] b0 a1 [2] 8f bd }

  condition:
    any of them
}