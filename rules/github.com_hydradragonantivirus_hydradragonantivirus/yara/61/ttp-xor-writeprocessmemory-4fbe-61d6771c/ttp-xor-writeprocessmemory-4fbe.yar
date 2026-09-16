rule TTP_XOR_WriteProcessMemory_4fbe {
  strings:
    $key_4fbe = { 18 cc [2] 2a ee [2] 2c db [2] 02 db [2] 3d c7 }

  condition:
    any of them
}