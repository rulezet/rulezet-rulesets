rule TTP_XOR_WriteProcessMemory_e26a {
  strings:
    $key_e26a = { b5 18 [2] 87 3a [2] 81 0f [2] af 0f [2] 90 13 }

  condition:
    any of them
}