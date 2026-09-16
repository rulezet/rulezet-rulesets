rule TTP_XOR_WriteProcessMemory_f81c {
  strings:
    $key_f81c = { af 6e [2] 9d 4c [2] 9b 79 [2] b5 79 [2] 8a 65 }

  condition:
    any of them
}