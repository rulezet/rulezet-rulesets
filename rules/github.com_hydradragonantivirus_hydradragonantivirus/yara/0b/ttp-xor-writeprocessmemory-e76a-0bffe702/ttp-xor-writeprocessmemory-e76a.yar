rule TTP_XOR_WriteProcessMemory_e76a {
  strings:
    $key_e76a = { b0 18 [2] 82 3a [2] 84 0f [2] aa 0f [2] 95 13 }

  condition:
    any of them
}