rule TTP_XOR_WriteProcessMemory_d994 {
  strings:
    $key_d994 = { 8e e6 [2] bc c4 [2] ba f1 [2] 94 f1 [2] ab ed }

  condition:
    any of them
}