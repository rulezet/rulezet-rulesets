rule TTP_XOR_WriteProcessMemory_dfea {
  strings:
    $key_dfea = { 88 98 [2] ba ba [2] bc 8f [2] 92 8f [2] ad 93 }

  condition:
    any of them
}