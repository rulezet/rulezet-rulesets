rule TTP_XOR_WriteProcessMemory_f81a {
  strings:
    $key_f81a = { af 68 [2] 9d 4a [2] 9b 7f [2] b5 7f [2] 8a 63 }

  condition:
    any of them
}