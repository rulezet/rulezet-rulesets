rule TTP_XOR_WriteProcessMemory_d9cf {
  strings:
    $key_d9cf = { 8e bd [2] bc 9f [2] ba aa [2] 94 aa [2] ab b6 }

  condition:
    any of them
}