rule TTP_XOR_WriteProcessMemory_f81d {
  strings:
    $key_f81d = { af 6f [2] 9d 4d [2] 9b 78 [2] b5 78 [2] 8a 64 }

  condition:
    any of them
}