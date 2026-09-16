rule TTP_XOR_WriteProcessMemory_f838 {
  strings:
    $key_f838 = { af 4a [2] 9d 68 [2] 9b 5d [2] b5 5d [2] 8a 41 }

  condition:
    any of them
}