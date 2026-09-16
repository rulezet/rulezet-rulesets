rule TTP_XOR_WriteProcessMemory_dfed {
  strings:
    $key_dfed = { 88 9f [2] ba bd [2] bc 88 [2] 92 88 [2] ad 94 }

  condition:
    any of them
}