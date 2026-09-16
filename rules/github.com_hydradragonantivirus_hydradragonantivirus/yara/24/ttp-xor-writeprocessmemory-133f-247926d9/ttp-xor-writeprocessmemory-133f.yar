rule TTP_XOR_WriteProcessMemory_133f {
  strings:
    $key_133f = { 44 4d [2] 76 6f [2] 70 5a [2] 5e 5a [2] 61 46 }

  condition:
    any of them
}