rule TTP_XOR_WriteProcessMemory_cece {
  strings:
    $key_cece = { 99 bc [2] ab 9e [2] ad ab [2] 83 ab [2] bc b7 }

  condition:
    any of them
}