rule TTP_XOR_WriteProcessMemory_d9cd {
  strings:
    $key_d9cd = { 8e bf [2] bc 9d [2] ba a8 [2] 94 a8 [2] ab b4 }

  condition:
    any of them
}