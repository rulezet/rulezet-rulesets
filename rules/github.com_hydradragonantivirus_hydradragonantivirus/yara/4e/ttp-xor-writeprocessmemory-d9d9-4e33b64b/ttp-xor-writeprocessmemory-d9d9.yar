rule TTP_XOR_WriteProcessMemory_d9d9 {
  strings:
    $key_d9d9 = { 8e ab [2] bc 89 [2] ba bc [2] 94 bc [2] ab a0 }

  condition:
    any of them
}