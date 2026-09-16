rule TTP_XOR_WriteProcessMemory_e62a {
  strings:
    $key_e62a = { b1 58 [2] 83 7a [2] 85 4f [2] ab 4f [2] 94 53 }

  condition:
    any of them
}