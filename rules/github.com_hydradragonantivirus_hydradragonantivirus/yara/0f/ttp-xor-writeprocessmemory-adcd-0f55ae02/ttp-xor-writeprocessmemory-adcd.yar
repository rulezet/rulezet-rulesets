rule TTP_XOR_WriteProcessMemory_adcd {
  strings:
    $key_adcd = { fa bf [2] c8 9d [2] ce a8 [2] e0 a8 [2] df b4 }

  condition:
    any of them
}