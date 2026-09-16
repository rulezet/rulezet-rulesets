rule TTP_XOR_WriteProcessMemory_312a {
  strings:
    $key_312a = { 66 58 [2] 54 7a [2] 52 4f [2] 7c 4f [2] 43 53 }

  condition:
    any of them
}