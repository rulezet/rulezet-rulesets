rule TTP_XOR_WriteProcessMemory_ef7a {
  strings:
    $key_ef7a = { b8 08 [2] 8a 2a [2] 8c 1f [2] a2 1f [2] 9d 03 }

  condition:
    any of them
}