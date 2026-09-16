rule TTP_XOR_WriteProcessMemory_097a {
  strings:
    $key_097a = { 5e 08 [2] 6c 2a [2] 6a 1f [2] 44 1f [2] 7b 03 }

  condition:
    any of them
}