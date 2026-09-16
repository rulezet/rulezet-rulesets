rule TTP_XOR_WriteProcessMemory_e64a {
  strings:
    $key_e64a = { b1 38 [2] 83 1a [2] 85 2f [2] ab 2f [2] 94 33 }

  condition:
    any of them
}