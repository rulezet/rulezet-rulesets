rule TTP_XOR_WriteProcessMemory_f80f {
  strings:
    $key_f80f = { af 7d [2] 9d 5f [2] 9b 6a [2] b5 6a [2] 8a 76 }

  condition:
    any of them
}