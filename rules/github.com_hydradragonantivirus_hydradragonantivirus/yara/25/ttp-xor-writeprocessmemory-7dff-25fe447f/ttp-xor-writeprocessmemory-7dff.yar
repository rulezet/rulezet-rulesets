rule TTP_XOR_WriteProcessMemory_7dff {
  strings:
    $key_7dff = { 2a 8d [2] 18 af [2] 1e 9a [2] 30 9a [2] 0f 86 }

  condition:
    any of them
}