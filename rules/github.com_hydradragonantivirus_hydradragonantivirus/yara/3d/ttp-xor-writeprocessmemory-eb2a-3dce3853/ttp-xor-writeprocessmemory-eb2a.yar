rule TTP_XOR_WriteProcessMemory_eb2a {
  strings:
    $key_eb2a = { bc 58 [2] 8e 7a [2] 88 4f [2] a6 4f [2] 99 53 }

  condition:
    any of them
}