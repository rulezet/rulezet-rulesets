rule TTP_XOR_WriteProcessMemory_211f {
  strings:
    $key_211f = { 76 6d [2] 44 4f [2] 42 7a [2] 6c 7a [2] 53 66 }

  condition:
    any of them
}