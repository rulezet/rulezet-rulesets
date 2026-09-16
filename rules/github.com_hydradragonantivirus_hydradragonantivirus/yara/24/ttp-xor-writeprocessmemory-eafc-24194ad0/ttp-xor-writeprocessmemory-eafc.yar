rule TTP_XOR_WriteProcessMemory_eafc {
  strings:
    $key_eafc = { bd 8e [2] 8f ac [2] 89 99 [2] a7 99 [2] 98 85 }

  condition:
    any of them
}