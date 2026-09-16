rule TTP_XOR_WriteProcessMemory_c8cd {
  strings:
    $key_c8cd = { 9f bf [2] ad 9d [2] ab a8 [2] 85 a8 [2] ba b4 }

  condition:
    any of them
}