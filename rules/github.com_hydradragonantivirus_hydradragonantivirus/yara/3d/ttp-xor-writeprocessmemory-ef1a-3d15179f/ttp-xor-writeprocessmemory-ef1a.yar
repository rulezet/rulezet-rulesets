rule TTP_XOR_WriteProcessMemory_ef1a {
  strings:
    $key_ef1a = { b8 68 [2] 8a 4a [2] 8c 7f [2] a2 7f [2] 9d 63 }

  condition:
    any of them
}