rule TTP_XOR_WriteProcessMemory_379c {
  strings:
    $key_379c = { 60 ee [2] 52 cc [2] 54 f9 [2] 7a f9 [2] 45 e5 }

  condition:
    any of them
}