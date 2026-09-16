rule TTP_XOR_WriteProcessMemory_533f {
  strings:
    $key_533f = { 04 4d [2] 36 6f [2] 30 5a [2] 1e 5a [2] 21 46 }

  condition:
    any of them
}