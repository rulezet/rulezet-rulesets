rule TTP_XOR_WriteProcessMemory_f818 {
  strings:
    $key_f818 = { af 6a [2] 9d 48 [2] 9b 7d [2] b5 7d [2] 8a 61 }

  condition:
    any of them
}