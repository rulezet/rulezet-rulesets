rule TTP_XOR_WriteProcessMemory_eb3a {
  strings:
    $key_eb3a = { bc 48 [2] 8e 6a [2] 88 5f [2] a6 5f [2] 99 43 }

  condition:
    any of them
}