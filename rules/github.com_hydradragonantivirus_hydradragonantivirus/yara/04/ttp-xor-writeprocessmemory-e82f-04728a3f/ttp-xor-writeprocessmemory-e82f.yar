rule TTP_XOR_WriteProcessMemory_e82f {
  strings:
    $key_e82f = { bf 5d [2] 8d 7f [2] 8b 4a [2] a5 4a [2] 9a 56 }

  condition:
    any of them
}