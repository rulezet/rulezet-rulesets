rule TTP_XOR_WriteProcessMemory_eec1 {
  strings:
    $key_eec1 = { b9 b3 [2] 8b 91 [2] 8d a4 [2] a3 a4 [2] 9c b8 }

  condition:
    any of them
}