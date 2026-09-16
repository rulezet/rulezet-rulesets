rule TTP_XOR_WriteProcessMemory_dfbf {
  strings:
    $key_dfbf = { 88 cd [2] ba ef [2] bc da [2] 92 da [2] ad c6 }

  condition:
    any of them
}