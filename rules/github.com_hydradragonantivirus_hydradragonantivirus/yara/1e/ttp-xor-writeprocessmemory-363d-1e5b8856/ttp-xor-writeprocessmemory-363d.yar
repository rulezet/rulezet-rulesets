rule TTP_XOR_WriteProcessMemory_363d {
  strings:
    $key_363d = { 61 4f [2] 53 6d [2] 55 58 [2] 7b 58 [2] 44 44 }

  condition:
    any of them
}