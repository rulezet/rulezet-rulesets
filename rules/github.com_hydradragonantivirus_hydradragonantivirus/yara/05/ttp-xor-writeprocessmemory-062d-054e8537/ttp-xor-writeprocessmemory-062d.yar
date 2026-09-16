rule TTP_XOR_WriteProcessMemory_062d {
  strings:
    $key_062d = { 51 5f [2] 63 7d [2] 65 48 [2] 4b 48 [2] 74 54 }

  condition:
    any of them
}