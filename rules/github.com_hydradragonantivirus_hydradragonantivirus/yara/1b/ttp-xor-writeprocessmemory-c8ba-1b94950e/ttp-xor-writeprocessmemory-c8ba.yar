rule TTP_XOR_WriteProcessMemory_c8ba {
  strings:
    $key_c8ba = { 9f c8 [2] ad ea [2] ab df [2] 85 df [2] ba c3 }

  condition:
    any of them
}