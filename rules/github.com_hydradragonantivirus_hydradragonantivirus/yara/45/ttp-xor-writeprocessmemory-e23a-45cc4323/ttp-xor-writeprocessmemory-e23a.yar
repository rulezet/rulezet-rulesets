rule TTP_XOR_WriteProcessMemory_e23a {
  strings:
    $key_e23a = { b5 48 [2] 87 6a [2] 81 5f [2] af 5f [2] 90 43 }

  condition:
    any of them
}