rule TTP_XOR_WriteProcessMemory_cee4 {
  strings:
    $key_cee4 = { 99 96 [2] ab b4 [2] ad 81 [2] 83 81 [2] bc 9d }

  condition:
    any of them
}