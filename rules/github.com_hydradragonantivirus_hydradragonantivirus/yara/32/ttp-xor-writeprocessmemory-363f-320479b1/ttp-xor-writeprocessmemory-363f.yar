rule TTP_XOR_WriteProcessMemory_363f {
  strings:
    $key_363f = { 61 4d [2] 53 6f [2] 55 5a [2] 7b 5a [2] 44 46 }

  condition:
    any of them
}