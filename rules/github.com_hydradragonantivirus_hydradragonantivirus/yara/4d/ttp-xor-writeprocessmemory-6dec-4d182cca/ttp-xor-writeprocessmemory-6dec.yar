rule TTP_XOR_WriteProcessMemory_6dec {
  strings:
    $key_6dec = { 3a 9e [2] 08 bc [2] 0e 89 [2] 20 89 [2] 1f 95 }

  condition:
    any of them
}