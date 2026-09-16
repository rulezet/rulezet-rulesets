rule TTP_XOR_WriteProcessMemory_ffdd {
  strings:
    $key_ffdd = { a8 af [2] 9a 8d [2] 9c b8 [2] b2 b8 [2] 8d a4 }

  condition:
    any of them
}