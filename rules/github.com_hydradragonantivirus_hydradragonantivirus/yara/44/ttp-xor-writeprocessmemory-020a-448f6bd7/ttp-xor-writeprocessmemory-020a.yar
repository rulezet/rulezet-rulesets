rule TTP_XOR_WriteProcessMemory_020a {
  strings:
    $key_020a = { 55 78 [2] 67 5a [2] 61 6f [2] 4f 6f [2] 70 73 }

  condition:
    any of them
}