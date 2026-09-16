rule TTP_XOR_WriteProcessMemory_f84d {
  strings:
    $key_f84d = { af 3f [2] 9d 1d [2] 9b 28 [2] b5 28 [2] 8a 34 }

  condition:
    any of them
}