rule TTP_XOR_WriteProcessMemory_ced8 {
  strings:
    $key_ced8 = { 99 aa [2] ab 88 [2] ad bd [2] 83 bd [2] bc a1 }

  condition:
    any of them
}