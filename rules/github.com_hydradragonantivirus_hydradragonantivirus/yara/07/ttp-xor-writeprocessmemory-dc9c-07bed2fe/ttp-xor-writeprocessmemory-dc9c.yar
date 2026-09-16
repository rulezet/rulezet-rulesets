rule TTP_XOR_WriteProcessMemory_dc9c {
  strings:
    $key_dc9c = { 8b ee [2] b9 cc [2] bf f9 [2] 91 f9 [2] ae e5 }

  condition:
    any of them
}