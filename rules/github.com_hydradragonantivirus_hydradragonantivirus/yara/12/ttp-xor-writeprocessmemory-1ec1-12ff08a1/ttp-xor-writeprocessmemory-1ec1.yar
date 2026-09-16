rule TTP_XOR_WriteProcessMemory_1ec1 {
  strings:
    $key_1ec1 = { 49 b3 [2] 7b 91 [2] 7d a4 [2] 53 a4 [2] 6c b8 }

  condition:
    any of them
}