rule TTP_XOR_WriteProcessMemory_d9c9 {
  strings:
    $key_d9c9 = { 8e bb [2] bc 99 [2] ba ac [2] 94 ac [2] ab b0 }

  condition:
    any of them
}