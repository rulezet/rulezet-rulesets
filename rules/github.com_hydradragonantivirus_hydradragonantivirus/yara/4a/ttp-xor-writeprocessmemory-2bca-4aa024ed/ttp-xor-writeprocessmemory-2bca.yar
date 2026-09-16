rule TTP_XOR_WriteProcessMemory_2bca {
  strings:
    $key_2bca = { 7c b8 [2] 4e 9a [2] 48 af [2] 66 af [2] 59 b3 }

  condition:
    any of them
}