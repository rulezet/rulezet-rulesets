rule TTP_XOR_WriteProcessMemory_aac8 {
  strings:
    $key_aac8 = { fd ba [2] cf 98 [2] c9 ad [2] e7 ad [2] d8 b1 }

  condition:
    any of them
}