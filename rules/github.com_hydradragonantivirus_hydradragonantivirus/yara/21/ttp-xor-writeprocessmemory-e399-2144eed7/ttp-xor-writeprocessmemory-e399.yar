rule TTP_XOR_WriteProcessMemory_e399 {
  strings:
    $key_e399 = { b4 eb [2] 86 c9 [2] 80 fc [2] ae fc [2] 91 e0 }

  condition:
    any of them
}