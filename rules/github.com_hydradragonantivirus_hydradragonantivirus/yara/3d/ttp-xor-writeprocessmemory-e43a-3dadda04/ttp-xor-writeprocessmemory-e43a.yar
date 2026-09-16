rule TTP_XOR_WriteProcessMemory_e43a {
  strings:
    $key_e43a = { b3 48 [2] 81 6a [2] 87 5f [2] a9 5f [2] 96 43 }

  condition:
    any of them
}