rule TTP_XOR_WriteProcessMemory_fec1 {
  strings:
    $key_fec1 = { a9 b3 [2] 9b 91 [2] 9d a4 [2] b3 a4 [2] 8c b8 }

  condition:
    any of them
}