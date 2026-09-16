rule TTP_XOR_WriteProcessMemory_eb7a {
  strings:
    $key_eb7a = { bc 08 [2] 8e 2a [2] 88 1f [2] a6 1f [2] 99 03 }

  condition:
    any of them
}